//! Per-rank message collector with deduplication and truncation.
//! Port of `node/consensus/global/message_collector.go`.
//!
//! Messages are buffered per consensus rank. The leader provider
//! drains the buffer for the current rank when producing a frame.
//! Messages older than the retention window are automatically pruned.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use sha3::{Digest, Sha3_256};

// NOTE: global consensus has NO per-frame request cap. The original
// 100-message cap existed because a global proposal was gossiped and
// BlossomSub has a ~1 MiB message-size ceiling; global consensus now
// uses the direct point-to-point :8340 transport (see
// `direct_global_consensus_publisher`), which has no such ceiling. A
// proposal is bounded by bytes instead: what does not fit its budget waits
// for a later frame ([`MessageCollector::snapshot_for_proposal`]). App-shard consensus keeps its own
// cap (`MAX_APP_MESSAGES_PER_RANK` in `app_engine`); this collector is
// global-only.

/// Number of ranks to retain before pruning (matches Go's retention window).
/// The public GLOBAL collector counts it in finalized frames
/// ([`MessageCollector::prune_after_finalization`]).
const RETENTION_WINDOW: u64 = 10;

/// The one shard frame a message carries.
#[derive(Clone)]
struct ShardFrame {
    address: Vec<u8>,
    frame: u64,
    /// The GLOBAL frame it anchors to (`global_frame_number`).
    anchor: u64,
}

/// A collected message with its identity ([`message_key`]) for deduplication.
#[derive(Clone)]
struct CollectedMessage {
    data: Vec<u8>,
    hash: [u8; 32],
    /// The one shard frame it carries; `None` for anything else, including a
    /// bundle of several.
    shard: Option<ShardFrame>,
    /// It carries shard frames (reward proofs), one or several.
    proof: bool,
    /// Its shard frames passed the collector's verifier (or that of the public
    /// collector a private proposal copied it from).
    verified: bool,
}

impl CollectedMessage {
    fn new(data: Vec<u8>) -> Self {
        let mut checks = extract_shard_frame_checks(&data);
        let proof = !checks.is_empty();
        let shard = if checks.len() == 1 {
            checks.pop().map(|c| ShardFrame { address: c.address, frame: c.frame_number, anchor: c.global_frame_number })
        } else {
            None
        };
        Self { hash: message_key(&data), data, shard, proof, verified: false }
    }
}

/// The identity of a message for deduplication and consumption: a bundle's
/// requests without its timestamp, so a copy of the same requests sent again
/// (a seal republished every minute, a header resent) is the same message and
/// leaves with it. Nothing executes the timestamp. Anything else is its bytes.
fn message_key(data: &[u8]) -> [u8; 32] {
    use quil_execution::message_envelope::CanonicalMessageBundle;
    match CanonicalMessageBundle::from_canonical_bytes(data) {
        Ok(mut bundle) => {
            bundle.timestamp = 0;
            bundle.to_canonical_bytes().map_or_else(|_| sha256(data), |bytes| sha256(&bytes))
        }
        Err(_) => sha256(data),
    }
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
    /// Held messages by arrival number, so in arrival order.
    messages: BTreeMap<u64, CollectedMessage>,
    /// Each held message's key, with its arrival number.
    seen: HashMap<[u8; 32], u64>,
    /// The verified subset of `seen`.
    verified: HashSet<[u8; 32]>,
    /// Keys of the single-shard proofs held, by shard address: a verified
    /// frame finds what it supersedes without reading every held message.
    by_shard: HashMap<Vec<u8>, HashSet<[u8; 32]>>,
    bytes: usize,
    arrivals: u64,
}

/// Drop `message`'s entries from a buffer's indexes.
fn unindex(
    seen: &mut HashMap<[u8; 32], u64>, verified: &mut HashSet<[u8; 32]>,
    by_shard: &mut HashMap<Vec<u8>, HashSet<[u8; 32]>>, bytes: &mut usize, message: &CollectedMessage,
) {
    seen.remove(&message.hash);
    verified.remove(&message.hash);
    if let Some(shard) = &message.shard {
        if let Some(keys) = by_shard.get_mut(&shard.address) {
            keys.remove(&message.hash);
            if keys.is_empty() {
                by_shard.remove(&shard.address);
            }
        }
    }
    *bytes -= message.data.len();
}

impl RankBuffer {
    fn new() -> Self {
        Self {
            messages: BTreeMap::new(),
            seen: HashMap::new(),
            verified: HashSet::new(),
            by_shard: HashMap::new(),
            bytes: 0,
            arrivals: 0,
        }
    }

    /// Add a message if not already seen and the rank isn't over its cap.
    fn add(&mut self, message: CollectedMessage) -> AddOutcome {
        if self.seen.contains_key(&message.hash) {
            return AddOutcome::Duplicate;
        }
        if self.messages.len() >= MAX_MESSAGES_PER_RANK
            || self.bytes.saturating_add(message.data.len()) > MAX_BYTES_PER_RANK
        {
            return AddOutcome::Full;
        }
        let arrival = self.arrivals;
        self.arrivals += 1;
        self.seen.insert(message.hash, arrival);
        if message.verified {
            self.verified.insert(message.hash);
        }
        if let Some(shard) = &message.shard {
            self.by_shard.entry(shard.address.clone()).or_default().insert(message.hash);
        }
        self.bytes += message.data.len();
        self.messages.insert(arrival, message);
        AddOutcome::Added
    }

    /// Keep only the messages `keep` accepts.
    fn retain(&mut self, keep: impl Fn(&CollectedMessage) -> bool) {
        let (seen, verified, by_shard, bytes) =
            (&mut self.seen, &mut self.verified, &mut self.by_shard, &mut self.bytes);
        self.messages.retain(|_, m| {
            let kept = keep(m);
            if !kept {
                unindex(seen, verified, by_shard, bytes, m);
            }
            kept
        });
    }

    /// Remove the message with `key`.
    fn take(&mut self, key: &[u8; 32]) -> Option<CollectedMessage> {
        let message = self.messages.remove(self.seen.get(key)?)?;
        unindex(&mut self.seen, &mut self.verified, &mut self.by_shard, &mut self.bytes, &message);
        Some(message)
    }

    /// The single-shard proof with `key`'s shard frame.
    fn shard_frame(&self, key: &[u8; 32]) -> Option<&ShardFrame> {
        self.messages.get(self.seen.get(key)?)?.shard.as_ref()
    }

    fn contains(&self, key: &[u8; 32]) -> bool {
        self.seen.contains_key(key)
    }

    /// Held messages in arrival order, with their arrival numbers.
    fn iter(&self) -> impl Iterator<Item = (u64, &CollectedMessage)> {
        self.messages.iter().map(|(arrival, m)| (*arrival, m))
    }

    fn into_messages(self) -> impl Iterator<Item = CollectedMessage> {
        self.messages.into_values()
    }

    fn len(&self) -> usize {
        self.messages.len()
    }

    fn is_empty(&self) -> bool {
        self.messages.is_empty()
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
    /// Rejected by a real filter; the message was NOT retained.
    Filtered(Refusal),
}

/// Why a submission was not retained. A submitter cannot read the
/// receiver's log, so a submit handler returns [`Refusal::reason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Prover-only mode (degraded coverage) and not a prover message.
    ProverOnly,
    /// A shard frame's address is not in this node's committed shard set,
    /// which a node still executing older frames has not reached yet.
    UnknownShard,
    /// The rank's count or byte cap is reached.
    RankFull,
    /// A shard frame failed verification against committed state.
    InvalidShardFrame,
}

impl Refusal {
    pub fn reason(self) -> &'static str {
        match self {
            Self::ProverOnly => "prover-only mode admits prover messages only",
            Self::UnknownShard => "shard frame address not in this node's committed shard set",
            Self::RankFull => "rank buffer full",
            Self::InvalidShardFrame => "shard frame failed verification",
        }
    }

    /// The same message may be accepted later: the submitter should retry.
    pub fn retryable(self) -> bool {
        matches!(self, Self::RankFull)
    }
}

/// A verifier's judgement of the shard frames a bundle carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardFrameVerdict {
    /// Every shard frame is certified and valid in committed state.
    Valid,
    /// A shard frame is invalid (for example, a forged certificate).
    Invalid(String),
    /// Committed state cannot judge it now; it may be valid later.
    Unavailable(String),
}

/// Verifies the shard frames of a bundle ([`MessageCollector::set_shard_frame_verifier`]).
pub type ShardFrameVerifier = std::sync::Arc<dyn Fn(&[u8]) -> ShardFrameVerdict + Send + Sync>;

/// Shard-frame verifications run at once; past it, frames are held
/// unverified.
const MAX_CONCURRENT_VERIFICATIONS: usize = 4;

/// How long a copy of a shard frame under verification waits for that
/// verdict before it is held unverified.
const VERIFICATION_WAIT: Duration = Duration::from_secs(2);

/// Why a copy of a shard frame was not claimed for verification
/// ([`MessageCollector::claim_verification`]).
enum Unclaimed {
    /// The verdict on another copy superseded it.
    Superseded,
    /// Another copy was still under verification after [`VERIFICATION_WAIT`].
    Busy,
}

/// A claim on verifying one shard frame ([`MessageCollector::claim_verification`]),
/// released however the admission ends.
struct VerificationClaim<'a> {
    collector: &'a MessageCollector,
    frame: (Vec<u8>, u64),
}

impl Drop for VerificationClaim<'_> {
    fn drop(&mut self) {
        self.collector.verifying.lock().unwrap().remove(&self.frame);
        self.collector.verification_ended.notify_all();
    }
}

/// A message a proposal may copy: its rank, arrival number and contents.
type Candidate<'a> = (u64, u64, &'a CollectedMessage);

/// What a proposal copy has taken so far.
struct Copied<'a> {
    taken: Vec<Candidate<'a>>,
    bytes: usize,
    max_items: usize,
}

impl<'a> Copied<'a> {
    /// Take all of `candidates` if together they fit under `cap` bytes.
    fn take(&mut self, candidates: Vec<Candidate<'a>>, cap: usize) -> bool {
        let bytes: usize = candidates.iter().map(|c| c.2.data.len()).sum();
        let fits = self.taken.len() + candidates.len() <= self.max_items
            && self.bytes.saturating_add(bytes) <= cap;
        if fits {
            self.bytes += bytes;
            self.taken.extend(candidates);
        }
        fits
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
    /// Ranks of the latest finalized frames, oldest first, at most
    /// `RETENTION_WINDOW + 1` ([`Self::prune_after_finalization`]).
    finalized_ranks: std::sync::Mutex<VecDeque<u64>>,
    /// Admission check of shard frames. With one installed, a shard frame is
    /// held only once verified, and a verified frame supersedes its shard's
    /// lower frames: a stall then holds one proof per shard instead of every
    /// member's copy of every frame, and no forged header can stand in for a
    /// real one.
    shard_frame_verifier: RwLock<Option<ShardFrameVerifier>>,
    verifications: std::sync::atomic::AtomicUsize,
    /// Highest VERIFIED frame admitted per shard address. Only verified
    /// frames move it: an unverified height would let an invalid candidate
    /// suppress valid frames.
    verified_tips: std::sync::Mutex<HashMap<Vec<u8>, u64>>,
    /// Single-shard frames under verification now, `(address, frame)`.
    /// Members' copies of a frame differ (each certificate can carry other
    /// signers) and arrive together; a copy waits for the verdict on the
    /// first instead of taking a verification of its own.
    verifying: std::sync::Mutex<HashSet<(Vec<u8>, u64)>>,
    verification_ended: std::sync::Condvar,
    /// When each shard's proof last rode a finalized frame, numbered by the
    /// finalizations this collector has seen. A proposal over its budget
    /// takes the shards that have waited longest.
    included: std::sync::Mutex<HashMap<Vec<u8>, u64>>,
    finalizations: std::sync::atomic::AtomicU64,
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
            finalized_ranks: std::sync::Mutex::new(VecDeque::new()),
            shard_frame_verifier: RwLock::new(None),
            verifications: std::sync::atomic::AtomicUsize::new(0),
            verified_tips: std::sync::Mutex::new(HashMap::new()),
            verifying: std::sync::Mutex::new(HashSet::new()),
            verification_ended: std::sync::Condvar::new(),
            included: std::sync::Mutex::new(HashMap::new()),
            finalizations: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Install the admission check of shard frames. Archives, whose collector
    /// feeds GLOBAL proposals, verify against committed state.
    pub fn set_shard_frame_verifier(&self, verifier: ShardFrameVerifier) {
        *self.shard_frame_verifier.write().unwrap() = Some(verifier);
    }

    /// `data` carries shard frames this collector would verify before holding
    /// them: a caller on an async runtime admits it off the runtime.
    pub fn requires_verification(&self, data: &[u8]) -> bool {
        if self.shard_frame_verifier.read().unwrap().is_none() {
            return false;
        }
        let keys = extract_shard_frame_keys(data);
        !keys.is_empty() && !self.superseded(&keys)
    }

    /// Every frame in `keys` is at or below a verified frame of its shard.
    fn superseded(&self, keys: &[(Vec<u8>, u64)]) -> bool {
        let tips = self.verified_tips.lock().unwrap();
        keys.iter().all(|(address, frame)| tips.get(address).is_some_and(|tip| frame <= tip))
    }

    /// Whether the collector holds `data` as verified.
    pub fn is_verified(&self, data: &[u8]) -> bool {
        let key = message_key(data);
        self.buffers.read().unwrap().values().any(|b| b.verified.contains(&key))
    }

    /// Claim the verification of `shard`'s frame, waiting while another copy
    /// of it is verified, for that verdict or at most [`VERIFICATION_WAIT`].
    fn claim_verification(
        &self, shard: &ShardFrame, keys: &[(Vec<u8>, u64)],
    ) -> Result<VerificationClaim<'_>, Unclaimed> {
        let frame = (shard.address.clone(), shard.frame);
        let deadline = Instant::now() + VERIFICATION_WAIT;
        loop {
            let mut verifying = self.verifying.lock().unwrap();
            if verifying.insert(frame.clone()) {
                return Ok(VerificationClaim { collector: self, frame });
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(Unclaimed::Busy);
            }
            drop(self.verification_ended.wait_timeout(verifying, left).unwrap());
            if self.superseded(keys) {
                return Err(Unclaimed::Superseded);
            }
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
                for message in buffer.into_messages() {
                    merged.add(message);
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
        if !addresses.is_empty() {
            self.verified_tips.lock().unwrap().retain(|address, _| addresses.contains(address));
            self.included.lock().unwrap().retain(|address, _| addresses.contains(address));
        }
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

    /// Add a message the collector it was copied from held as verified (a
    /// private proposal copy, which has no verifier of its own).
    pub fn add_verified_message(&self, rank: u64, data: Vec<u8>) -> bool {
        matches!(self.admit(rank, data, true), SubmitOutcome::Accepted)
    }

    /// Add a message, distinguishing "newly accepted" from "we already
    /// hold it" from "filtered out". A network
    /// submit handler should treat both `Accepted` and `Duplicate` as
    /// SUCCESS — re-delivering something the collector already has (or has
    /// superseded) is not a dropped message; only `Filtered` is a real
    /// rejection. This is what stops a prover's idempotent re-submission
    /// of an already-delivered bundle from being reported to it as a
    /// transport failure.
    ///
    /// With a shard-frame verifier installed this verifies shard frames,
    /// which can take milliseconds: see [`Self::requires_verification`].
    pub fn add_message_outcome(&self, rank: u64, data: Vec<u8>) -> SubmitOutcome {
        self.admit(rank, data, false)
    }

    fn admit(&self, rank: u64, data: Vec<u8>, verified: bool) -> SubmitOutcome {
        // Prover-only mode filtering: check if the message is a
        // prover-protocol op (type prefix 0x0301-0x031A). If not,
        // reject it during degraded coverage.
        if self.prover_only_mode.load(std::sync::atomic::Ordering::Relaxed) {
            if !is_prover_message(&data) {
                tracing::debug!(
                    "message collector: submit rejected — prover-only (degraded coverage) mode, non-prover message"
                );
                return SubmitOutcome::Filtered(Refusal::ProverOnly);
            }
        }

        let mut message = CollectedMessage::new(data);
        // Already included in a finalized frame → never re-accept. This
        // is what stops a message from re-entering the mempool after it
        // has been consumed by a committed frame. The archive already has
        // this work, so this is a duplicate, not a rejection.
        if self.finalized.read().unwrap().contains(&message.hash) {
            return SubmitOutcome::Duplicate;
        }

        let checks = extract_shard_frame_checks(&message.data);

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
                    // The whole address: every shard of an application shares
                    // its first 32 bytes, so a prefix names none of them.
                    tracing::warn!(
                        address = %hex::encode(&c.address),
                        frame_number = c.frame_number,
                        valid_shard_count = valid.len(),
                        "message collector: shard-frame submit REJECTED — address not in current valid-shard set (stale / pre-split / wrong-grid address)"
                    );
                    return SubmitOutcome::Filtered(Refusal::UnknownShard);
                }
            }
        }

        // A frame at or below a verified frame of its shard adds nothing: the
        // leader carries one proof per shard, the highest. Another member's
        // copy of the same frame lands here too.
        let keys: Vec<(Vec<u8>, u64)> = checks.iter().map(|c| (c.address.clone(), c.frame_number)).collect();
        if !keys.is_empty() && self.superseded(&keys) {
            return SubmitOutcome::Duplicate;
        }
        if self.buffers.read().unwrap().values().any(|b| b.contains(&message.hash)) {
            return SubmitOutcome::Duplicate;
        }

        // Verify before holding when it can be now: an unverified header
        // cannot stand in for a real one, and only a verified one supersedes.
        // One that cannot be verified now (state unavailable, the verifier
        // busy, another copy's verdict slow) is held unverified, and the
        // leader verifies the one it picks, as without a verifier (a node
        // whose collector feeds no GLOBAL proposal). Refused instead, frames
        // outlived their GLOBAL window: every archive refused them at once
        // while an epoch's first frame published (2026-10-15).
        message.verified = verified;
        // Held until the message is filed (declared before the buffers'
        // lock, so released after it): a waiting copy then finds it superseded.
        let mut _claim = None;
        if !keys.is_empty() && !verified {
            let verifier = self.shard_frame_verifier.read().unwrap().clone();
            if let Some(verify) = verifier {
                use std::sync::atomic::{AtomicUsize, Ordering};
                let claimed = match &message.shard {
                    Some(shard) => match self.claim_verification(shard, &keys) {
                        Ok(claim) => {
                            _claim = Some(claim);
                            true
                        }
                        Err(Unclaimed::Superseded) => return SubmitOutcome::Duplicate,
                        Err(Unclaimed::Busy) => false,
                    },
                    None => true,
                };
                // Released however the verification ends.
                struct Slot<'a>(&'a AtomicUsize);
                impl Drop for Slot<'_> {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::AcqRel);
                    }
                }
                let slot = claimed.then(|| Slot(&self.verifications))
                    .filter(|slot| slot.0.fetch_add(1, Ordering::AcqRel) < MAX_CONCURRENT_VERIFICATIONS);
                if let Some(slot) = slot {
                    let verdict = verify(&message.data);
                    drop(slot);
                    match verdict {
                        ShardFrameVerdict::Valid => message.verified = true,
                        ShardFrameVerdict::Invalid(reason) => {
                            tracing::warn!(
                                shards = %keys.iter().map(|(a, f)| format!("{}@{f}", hex::encode(a))).collect::<Vec<_>>().join(","),
                                %reason,
                                "message collector: shard-frame submit REJECTED — verification failed"
                            );
                            return SubmitOutcome::Filtered(Refusal::InvalidShardFrame);
                        }
                        ShardFrameVerdict::Unavailable(reason) => {
                            tracing::debug!(%reason, "message collector: shard frame not verifiable now; held unverified");
                        }
                    }
                }
            }
        }

        // File nothing below the newest finalized frame: retention counts
        // finalized frames from the rank a message is filed at, and a submit
        // handler's rank lags them on an archive that has not finalized since
        // it started (rank 0) or is still catching up.
        let rank = self.finalized_ranks.lock().unwrap().back().map_or(rank, |last| rank.max(*last));
        let mut buffers = self.buffers.write().unwrap();
        // Another copy may have been verified while this one was.
        if message.verified && self.superseded(&keys) {
            return SubmitOutcome::Duplicate;
        }
        let (hash, verified) = (message.hash, message.verified);
        let ranks_held = buffers.len();
        let buffer = buffers.entry(rank).or_insert_with(RankBuffer::new);
        match buffer.add(message) {
            AddOutcome::Added => {
                if verified && !keys.is_empty() {
                    self.supersede(&mut buffers, &keys, hash);
                }
                SubmitOutcome::Accepted
            }
            AddOutcome::Duplicate => SubmitOutcome::Duplicate,
            AddOutcome::Full => {
                tracing::warn!(
                    rank,
                    pending = buffer.len(),
                    pending_bytes = buffer.bytes,
                    max_messages = MAX_MESSAGES_PER_RANK,
                    max_bytes = MAX_BYTES_PER_RANK,
                    ranks_held,
                    "message collector: submit rejected — rank buffer full (per-rank count/byte cap reached)"
                );
                SubmitOutcome::Filtered(Refusal::RankFull)
            }
        }
    }

    /// Raise the verified frame of each shard in `keys` and drop what it
    /// supersedes: the single-shard messages of those shards at or below it,
    /// except `keep`, the message that raised it. Found through each buffer's
    /// shard index: reading every held message instead cost each verified
    /// arrival time in proportion to the shard count, under the buffers' lock.
    fn supersede(&self, buffers: &mut HashMap<u64, RankBuffer>, keys: &[(Vec<u8>, u64)], keep: [u8; 32]) {
        let mut tips = self.verified_tips.lock().unwrap();
        for (address, frame) in keys {
            let tip = tips.entry(address.clone()).or_insert(*frame);
            *tip = (*tip).max(*frame);
        }
        for (address, _) in keys {
            let tip = tips[address];
            for buffer in buffers.values_mut() {
                let Some(held) = buffer.by_shard.get(address) else { continue };
                let below: Vec<[u8; 32]> = held
                    .iter()
                    .filter(|key| **key != keep && buffer.shard_frame(key).is_some_and(|s| s.frame <= tip))
                    .copied()
                    .collect();
                for key in below {
                    buffer.take(&key);
                }
            }
        }
        buffers.retain(|_, b| !b.is_empty());
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
                    for (_, m) in buf.iter() {
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
    /// state in the public collector: at most `max_items` messages and
    /// `max_bytes` bytes. What does not fit waits for a later proposal. The
    /// copy is returned in collection order (oldest rank first). A backlog
    /// over the budget must not fail the copy: the public buffers are pruned
    /// only after a finalized frame, so a restart's backlog would otherwise
    /// leave GLOBAL unable to make any private proposal, and therefore any
    /// frame, again.
    pub(crate) fn snapshot_for_execution(
        &self, rank: u64, max_bytes: usize, max_items: usize,
    ) -> quil_types::error::Result<Vec<Vec<u8>>> {
        Ok(self.snapshot_for_proposal(rank, max_bytes, max_items, None, &[])?
            .into_iter()
            .map(|(data, _)| data)
            .collect())
    }

    /// [`Self::snapshot_for_execution`] for a GLOBAL proposal of `frame`
    /// (`None` for any other proposal), with whether each message is held
    /// verified, so a private copy keeps that ([`Self::add_verified_message`]).
    ///
    /// The budget is shared, not first come first served. Shard proofs are
    /// guaranteed half of it and other messages (joins, leaves, kicks,
    /// settlements) the other half; either takes what the other leaves. Other
    /// messages go newest rank first. Shard proofs go a shard at a time, the
    /// shards whose proofs rode a finalized frame longest ago first and those
    /// `consumed` by an executed ancestor last, each with the candidates its
    /// leader would examine ([`select_shard_tips`]). Taken in arrival order
    /// (until 2026-10-15), one view's proofs from about 700 shards filled the
    /// budget: the shards whose proofs arrived late were left out of every
    /// frame, and no message from an older view was reached.
    ///
    /// Nothing `consumed` by an executed ancestor is copied, nor a shard proof
    /// `frame` cannot carry ([`anchor_in_lockstep`]).
    ///
    /// [`select_shard_tips`]: crate::leader_provider::select_shard_tips
    pub(crate) fn snapshot_for_proposal(
        &self, rank: u64, max_bytes: usize, max_items: usize,
        frame: Option<u64>, consumed: &[Vec<u8>],
    ) -> quil_types::error::Result<Vec<(Vec<u8>, bool)>> {
        use crate::leader_provider::MAX_TIP_VERIFICATIONS;
        use quil_types::error::QuilError;
        let unavailable = || QuilError::ExecutionUnavailable("proposal message snapshot lock failure".into());
        self.note_rank(rank);
        let consumed_keys: HashSet<[u8; 32]> = consumed.iter().map(|m| message_key(m)).collect();
        let just_included: HashSet<Vec<u8>> =
            consumed.iter().flat_map(|m| extract_shard_frame_keys(m)).map(|(address, _)| address).collect();
        let buffers = self.buffers.read().map_err(|_| unavailable())?;
        let finalized = self.finalized.read().map_err(|_| unavailable())?;
        let mut ranks: Vec<_> = buffers.keys().copied().filter(|r| *r <= rank).collect();
        ranks.sort_unstable_by(|a, b| b.cmp(a));
        let carried = |m: &CollectedMessage| match (frame, &m.shard) {
            (None, _) => true,
            (Some(frame), Some(shard)) => anchor_in_lockstep(shard.anchor, frame),
            (Some(frame), None) => bundle_shard_frames_in_lockstep(&m.data, frame),
        };
        let mut seen = HashSet::new();
        let (mut others, mut bundles) = (Vec::new(), Vec::new());
        let mut shards: HashMap<&[u8], Vec<Candidate>> = HashMap::new();
        for rank in ranks {
            for (arrival, m) in buffers[&rank].iter() {
                if finalized.contains(&m.hash) || consumed_keys.contains(&m.hash) || !seen.insert(m.hash) {
                    continue;
                }
                if !m.proof {
                    others.push((rank, arrival, m));
                } else if carried(m) {
                    match &m.shard {
                        Some(shard) => shards.entry(shard.address.as_slice()).or_default().push((rank, arrival, m)),
                        None => bundles.push((rank, arrival, m)),
                    }
                }
            }
        }
        let mut groups: Vec<((u64, [u8; 32]), Vec<Candidate>)> = {
            let included = self.included.lock().map_err(|_| unavailable())?;
            shards
                .into_iter()
                .map(|(address, mut candidates)| {
                    // Highest frame first; the stable sort keeps newer ranks first within one.
                    candidates.sort_by_key(|c| std::cmp::Reverse(c.2.shard.as_ref().map_or(0, |s| s.frame)));
                    let (mut picks, mut unverified) = (Vec::new(), 0);
                    for candidate in candidates {
                        if candidate.2.verified {
                            picks.push(candidate);
                            break;
                        }
                        if unverified < MAX_TIP_VERIFICATIONS {
                            unverified += 1;
                            picks.push(candidate);
                        }
                    }
                    let last = if just_included.contains(address) {
                        u64::MAX
                    } else {
                        included.get(address).copied().unwrap_or(0)
                    };
                    // Shards that waited as long take turns, view by view.
                    let turn = sha256(&[address, &rank.to_be_bytes()[..]].concat());
                    ((last, turn), picks)
                })
                .collect()
        };
        groups.sort_unstable_by(|a, b| a.0.cmp(&b.0));

        let size = |candidates: &[Candidate]| candidates.iter().map(|c| c.2.data.len()).sum::<usize>();
        let proof_bytes = size(&bundles) + groups.iter().map(|(_, picks)| size(picks)).sum::<usize>();
        let others_cap = max_bytes - proof_bytes.min(max_bytes / 2);
        let mut copied = Copied { taken: Vec::new(), bytes: 0, max_items };
        let mut waiting = Vec::new();
        for candidate in others {
            if !copied.take(vec![candidate], others_cap) {
                waiting.push(candidate);
            }
        }
        let proofs = bundles.len() + groups.len();
        let mut proofs_left = 0usize;
        for picks in bundles.into_iter().map(|c| vec![c]).chain(groups.into_iter().map(|(_, picks)| picks)) {
            if !copied.take(picks, max_bytes) {
                proofs_left += 1;
            }
        }
        let mut others_left = 0usize;
        for candidate in waiting {
            if !copied.take(vec![candidate], max_bytes) {
                others_left += 1;
            }
        }
        if proofs_left + others_left > 0 {
            match frame {
                Some(frame) => tracing::info!(
                    rank, frame, shards = proofs, shards_left = proofs_left, others_left,
                    bytes = copied.bytes, max_bytes, max_items,
                    "GLOBAL proposal budget full: messages left for a later frame",
                ),
                None => tracing::debug!(
                    rank, others_left, bytes = copied.bytes, max_bytes, max_items,
                    "proposal budget full: messages left for a later frame",
                ),
            }
        }
        let mut taken = copied.taken;
        taken.sort_unstable_by_key(|c| (c.0, c.1));
        Ok(taken.into_iter().map(|(_, _, m)| (m.data.clone(), m.verified)).collect())
    }

    /// Age public GLOBAL inputs only after a finalized frame has materialized.
    /// Tentative proposals use private snapshots and cannot advance this window.
    ///
    /// The window counts finalized frames, not views: a message is dropped
    /// once `RETENTION_WINDOW` frames have finalized after the rank it was
    /// filed at. Views that end without a frame age nothing, so what arrived
    /// during a stall, or before an archive's first finalization since it
    /// started, is still offered to the frames after it. Counted in views,
    /// the first frame after the 880,560 halt (2026-10-14) would have dropped
    /// every message it did not carry, each one already reported to its
    /// submitter as accepted.
    pub fn prune_after_finalization(&self, rank: u64) {
        let cutoff = {
            let mut ranks = self.finalized_ranks.lock().unwrap();
            if ranks.back().is_some_and(|last| *last >= rank) {
                return;
            }
            ranks.push_back(rank);
            while ranks.len() > RETENTION_WINDOW as usize + 1 {
                ranks.pop_front();
            }
            if ranks.len() <= RETENTION_WINDOW as usize {
                return;
            }
            ranks[0]
        };
        self.buffers.write().unwrap().retain(|&r, _| r >= cutoff);
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
        let hashes: HashSet<[u8; 32]> = raw_msgs.iter().map(|m| message_key(m)).collect();

        {
            let mut buffers = self.buffers.write().unwrap();
            for buf in buffers.values_mut() {
                buf.retain(|m| !hashes.contains(&m.hash));
            }
            buffers.retain(|_, b| !b.is_empty());
        }
        {
            let mut fin = self.finalized.write().unwrap();
            for h in hashes {
                fin.insert(h);
            }
        }
        let shards: HashSet<Vec<u8>> =
            raw_msgs.iter().flat_map(|m| extract_shard_frame_keys(m)).map(|(address, _)| address).collect();
        if !shards.is_empty() {
            let finalization = self.finalizations.fetch_add(1, std::sync::atomic::Ordering::AcqRel) + 1;
            let mut included = self.included.lock().unwrap();
            for address in shards {
                included.insert(address, finalization);
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
        let hashes: HashSet<[u8; 32]> = raw_msgs.iter().map(|m| message_key(m)).collect();
        let mut buffers = self.buffers.write().unwrap();
        for buf in buffers.values_mut() {
            buf.retain(|m| !hashes.contains(&m.hash));
        }
        buffers.retain(|_, b| !b.is_empty());
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
                .map(|data| CollectedMessage::new(data.clone()))
                .filter(|m| !finalized.contains(&m.hash) && seen.insert(m.hash))
                .collect()
        };
        let mut buffers = self.buffers.write().unwrap();
        let arrived = buffers.remove(&rank).unwrap_or_else(RankBuffer::new);
        let (mut rest_count, mut rest_bytes) = (arrived.len(), arrived.bytes);
        let mut target = RankBuffer::new();
        let mut moved = HashSet::new();
        for m in carried {
            let already = arrived.contains(&m.hash);
            let (count, bytes) = if already { (0, 0) } else { (1, m.data.len()) };
            if target.len() + rest_count + count > MAX_MESSAGES_PER_RANK
                || target.bytes + rest_bytes + bytes > MAX_BYTES_PER_RANK
            {
                continue;
            }
            if already {
                rest_count -= 1;
                rest_bytes -= m.data.len();
            }
            let hash = m.hash;
            if matches!(target.add(m), AddOutcome::Added) {
                moved.insert(hash);
            }
        }
        for m in arrived.into_messages() {
            if !moved.contains(&m.hash) {
                target.add(m);
            }
        }
        for buf in buffers.values_mut() {
            buf.retain(|m| !moved.contains(&m.hash));
        }
        buffers.insert(rank, target);
        buffers.retain(|_, b| !b.is_empty());
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

    let bundle = match CanonicalMessageBundle::from_canonical_bytes(data) {
        Ok(b) => b,
        Err(_) => return true,
    };
    for req in bundle.requests.into_iter().flatten() {
        if req.inner_type_prefix == TYPE_FRAME_HEADER {
            if let Ok(fh) = FrameHeader::from_canonical_bytes(&req.inner_bytes) {
                if !anchor_in_lockstep(fh.global_frame_number, frame_number) {
                    return false;
                }
            }
        }
    }
    true
}

/// A shard frame anchored to GLOBAL frame `anchor` may ride GLOBAL frame
/// `frame_number`. WINDOWED LOCKSTEP (must mirror the materializer's
/// `audit_storage_attestation` exactly, or a packed frame would be rejected by
/// followers → halt): a storage shard proof is includable iff its anchor is 0
/// (genesis/legacy) OR within `[expected - W, expected]`. Multi-member shards
/// anchor to `latest − K`, so a strict `== expected` is unsatisfiable; the
/// window absorbs K + transit.
pub fn anchor_in_lockstep(anchor: u64, frame_number: u64) -> bool {
    use quil_execution::global_intrinsic::frame_header::STORAGE_ANCHOR_LOCKSTEP_WINDOW;
    let expected = frame_number.saturating_sub(1);
    let oldest = expected.saturating_sub(STORAGE_ANCHOR_LOCKSTEP_WINDOW);
    anchor == 0 || (oldest..=expected).contains(&anchor)
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

    /// A bundle carrying shard `addr`'s frame `frame`; `copy` varies the
    /// certificate-bearing bytes (another member's copy) and `timestamp` the
    /// bundle around them.
    fn shard_bundle(addr: u8, frame: u64, copy: u64, timestamp: i64) -> Vec<u8> {
        use quil_execution::global_intrinsic::frame_header::{FrameHeader, TYPE_FRAME_HEADER};
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let fh = FrameHeader { address: vec![addr; 32], frame_number: frame, rank: copy, global_frame_number: 99, ..Default::default() };
        let req = CanonicalMessageRequest { inner_type_prefix: TYPE_FRAME_HEADER, inner_bytes: fh.to_canonical_bytes().unwrap() };
        CanonicalMessageBundle { requests: vec![Some(req)], timestamp }.to_canonical_bytes().unwrap()
    }

    fn counting_verifier(
        verdict: impl Fn(u64) -> ShardFrameVerdict + Send + Sync + 'static,
    ) -> (ShardFrameVerifier, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = calls.clone();
        let verifier: ShardFrameVerifier = std::sync::Arc::new(move |data: &[u8]| {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            verdict(extract_shard_frame_keys(data)[0].1)
        });
        (verifier, calls)
    }

    #[test]
    fn a_verified_frame_supersedes_its_shards_lower_frames_and_copies() {
        let mc = MessageCollector::new();
        let (verifier, calls) = counting_verifier(|_| ShardFrameVerdict::Valid);
        mc.set_shard_frame_verifier(verifier);
        let first = shard_bundle(0x11, 5, 0, 1);
        assert!(mc.requires_verification(&first));
        assert_eq!(mc.add_message_outcome(3, first.clone()), SubmitOutcome::Accepted);
        assert!(mc.is_verified(&first));
        // Another member's copy of frame 5, and an older frame: nothing new.
        assert!(!mc.requires_verification(&shard_bundle(0x11, 5, 1, 2)));
        assert_eq!(mc.add_message_outcome(3, shard_bundle(0x11, 5, 1, 2)), SubmitOutcome::Duplicate);
        assert_eq!(mc.add_message_outcome(3, shard_bundle(0x11, 4, 0, 3)), SubmitOutcome::Duplicate);
        assert_eq!(mc.add_message_outcome(3, shard_bundle(0x22, 9, 0, 4)), SubmitOutcome::Accepted);
        // A higher frame replaces the shard's held proof, at any rank.
        assert_eq!(mc.add_message_outcome(4, shard_bundle(0x11, 7, 0, 5)), SubmitOutcome::Accepted);
        assert_eq!(mc.total_pending(), 2);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3, "copies and older frames skip verification");
        let mut held: Vec<_> = mc.collect_for_rank(4).iter().map(|m| extract_shard_frame_keys(m)[0].clone()).collect();
        held.sort();
        assert_eq!(held, vec![(vec![0x11; 32], 7), (vec![0x22; 32], 9)]);
    }

    #[test]
    fn a_forged_shard_frame_is_refused_and_moves_nothing() {
        let mc = MessageCollector::new();
        let (verifier, _) = counting_verifier(|frame| {
            if frame >= 100 { ShardFrameVerdict::Invalid("certificate".into()) } else { ShardFrameVerdict::Valid }
        });
        mc.set_shard_frame_verifier(verifier);
        assert_eq!(mc.add_message_outcome(1, shard_bundle(0x11, 5, 0, 0)), SubmitOutcome::Accepted);
        let refused = mc.add_message_outcome(1, shard_bundle(0x11, 1_000, 0, 0));
        assert_eq!(refused, SubmitOutcome::Filtered(Refusal::InvalidShardFrame));
        assert!(!Refusal::InvalidShardFrame.retryable());
        assert_eq!(mc.total_pending(), 1, "the real proof is still held");
        assert_eq!(mc.add_message_outcome(1, shard_bundle(0x11, 6, 0, 0)), SubmitOutcome::Accepted);
        assert_eq!(mc.total_pending(), 1);
    }

    #[test]
    fn unverifiable_shard_frames_are_held_unverified() {
        let mc = MessageCollector::new();
        let (verifier, _) = counting_verifier(|_| ShardFrameVerdict::Unavailable("state".into()));
        mc.set_shard_frame_verifier(verifier);
        assert_eq!(mc.add_message_outcome(1, shard_bundle(0x11, 5, 0, 0)), SubmitOutcome::Accepted);
        assert_eq!(mc.add_message_outcome(1, shard_bundle(0x11, 4, 0, 0)), SubmitOutcome::Accepted);
        assert_eq!(mc.total_pending(), 2, "an unverified frame supersedes nothing");
        assert!(!mc.is_verified(&shard_bundle(0x11, 5, 0, 0)));
        assert!(Refusal::RankFull.retryable() && !Refusal::InvalidShardFrame.retryable());
        // Without a verifier, frames are held unverified and supersede nothing.
        let plain = MessageCollector::new();
        assert!(!plain.requires_verification(&shard_bundle(0x11, 5, 0, 0)));
        assert!(plain.add_message(1, shard_bundle(0x11, 5, 0, 0)));
        assert!(plain.add_message(1, shard_bundle(0x11, 4, 0, 0)));
        assert!(!plain.is_verified(&shard_bundle(0x11, 5, 0, 0)));
    }

    #[test]
    fn copies_of_the_same_requests_are_one_message() {
        use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
        let bundle = |timestamp: i64| {
            let req = CanonicalMessageRequest { inner_type_prefix: 0x0301, inner_bytes: b"join".to_vec() };
            CanonicalMessageBundle { requests: vec![Some(req)], timestamp }.to_canonical_bytes().unwrap()
        };
        let mc = MessageCollector::new();
        assert_eq!(mc.add_message_outcome(1, bundle(1)), SubmitOutcome::Accepted);
        assert_eq!(mc.add_message_outcome(2, bundle(2)), SubmitOutcome::Duplicate, "resent a minute later");
        mc.mark_finalized(&[bundle(3)]);
        assert_eq!(mc.total_pending(), 0, "consumed by any copy");
        assert_eq!(mc.add_message_outcome(3, bundle(4)), SubmitOutcome::Duplicate);
    }

    #[test]
    fn a_private_copy_keeps_what_was_verified() {
        let public = MessageCollector::new();
        let (verifier, _) = counting_verifier(|_| ShardFrameVerdict::Valid);
        public.set_shard_frame_verifier(verifier);
        assert!(public.add_message(1, shard_bundle(0x11, 5, 0, 0)));
        assert!(public.add_message(1, b"plain".to_vec()));
        let copy = MessageCollector::new();
        for (data, verified) in public.snapshot_for_proposal(2, 4096, 100, None, &[]).unwrap() {
            if verified { copy.add_verified_message(2, data); } else { copy.add_message(2, data); }
        }
        assert!(copy.is_verified(&shard_bundle(0x11, 5, 0, 0)));
        assert!(!copy.is_verified(b"plain"));
        assert_eq!(copy.add_message_outcome(2, shard_bundle(0x11, 4, 0, 0)), SubmitOutcome::Duplicate);
    }

    #[test]
    fn a_stall_backlog_outlives_the_first_frame_after_it() {
        let mc = MessageCollector::new();
        for rank in 1..=11 {
            mc.prune_after_finalization(rank);
        }
        // Filed at the last finalized rank while views end without a frame.
        assert!(mc.add_message(11, b"backlog".to_vec()));
        assert_eq!(mc.snapshot_for_execution(400, 4096, 100).unwrap(), vec![b"backlog".to_vec()]);
        // Counted in views, the first frame after the stall dropped it.
        mc.prune_after_finalization(500);
        assert_eq!(mc.pending_count(11), 1);
        for rank in 501..=509 {
            mc.prune_after_finalization(rank);
        }
        assert_eq!(mc.pending_count(11), 1, "kept for ten finalized frames");
        mc.prune_after_finalization(510);
        assert_eq!(mc.pending_count(11), 0);
        // A replayed or older finalization ages nothing.
        assert!(mc.add_message(510, b"fresh".to_vec()));
        mc.prune_after_finalization(509);
        mc.prune_after_finalization(510);
        assert_eq!(mc.pending_count(510), 1);
    }

    #[test]
    fn arrivals_are_filed_no_older_than_the_newest_finalized_frame() {
        let mc = MessageCollector::new();
        // A restarted archive's submit handler files at rank 0 until it
        // finalizes a frame; it is kept for ten finalized frames.
        assert!(mc.add_message(0, b"early".to_vec()));
        for rank in 1000..1010 {
            mc.prune_after_finalization(rank);
        }
        assert_eq!(mc.pending_count(0), 1);
        // Later arrivals with the lagging rank are filed at the newest frame.
        assert!(mc.add_message(0, b"late".to_vec()));
        assert_eq!(mc.pending_count(1009), 1);
        assert!(!mc.add_message(3, b"late".to_vec()), "deduplicated at the filed rank");
        assert_eq!(mc.snapshot_for_execution(1010, 4096, 100).unwrap().len(), 2);
        mc.prune_after_finalization(1010);
        assert_eq!(mc.pending_count(0), 0);
        assert_eq!(mc.pending_count(1009), 1);
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
            SubmitOutcome::Filtered(Refusal::ProverOnly)
        );
        mc.set_prover_only_mode(false);
        // A rank over its byte cap refuses, and says so.
        assert_eq!(
            mc.add_message_outcome(4, vec![0; MAX_BYTES_PER_RANK + 1]),
            SubmitOutcome::Filtered(Refusal::RankFull)
        );
        assert_eq!(Refusal::RankFull.reason(), "rank buffer full");
        mc.set_prover_only_mode(true);
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
        assert_eq!(collector.add_message_outcome(1, bundle(&children[0].prefix, 1)), SubmitOutcome::Filtered(Refusal::UnknownShard));
        txn.commit().unwrap();
        collector.refresh_valid_shard_addresses(&shards).unwrap();
        for child in &children {
            assert_eq!(collector.add_message_outcome(1, bundle(&child.prefix, 1)), SubmitOutcome::Accepted);
        }
        assert_eq!(collector.add_message_outcome(1, bundle(&parent.prefix, 2)), SubmitOutcome::Filtered(Refusal::UnknownShard));

        let txn = clock.new_transaction(false).unwrap();
        for child in &children { shards.delete_app_shard(txn.as_ref(), &key, &child.prefix).unwrap(); }
        shards.put_app_shard(txn.as_ref(), &parent).unwrap();
        txn.commit().unwrap();
        collector.refresh_valid_shard_addresses(&shards).unwrap();
        assert_eq!(collector.add_message_outcome(1, bundle(&parent.prefix, 2)), SubmitOutcome::Accepted);
        assert_eq!(collector.add_message_outcome(1, bundle(&children[0].prefix, 2)), SubmitOutcome::Filtered(Refusal::UnknownShard));
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

    /// The shard address byte of each copied shard proof.
    fn shards_of(copy: &[Vec<u8>]) -> HashSet<u8> {
        copy.iter().filter_map(|m| extract_shard_frame_keys(m).first().map(|(address, _)| address[0])).collect()
    }

    /// Shard proofs and other messages each keep half a proposal's budget.
    /// Taken newest view first in arrival order, a view's proofs crowded out a
    /// join from the view before, and a flood of other messages every proof.
    #[test]
    fn shard_proofs_and_other_messages_each_keep_half_the_budget() {
        let mc = MessageCollector::new();
        let join = vec![0x03; 10];
        mc.add_message(1, join.clone());
        let proofs: Vec<_> = (1..=20u8).map(|shard| shard_bundle(shard, 5, 0, 0)).collect();
        for proof in &proofs {
            assert!(mc.add_message(2, proof.clone()));
        }
        let budget = 10 * proofs[0].len();
        let copy = mc.snapshot_for_execution(2, budget, 100).unwrap();
        assert!(copy.contains(&join), "the older join rides");
        assert_eq!(shards_of(&copy).len(), (budget - join.len()) / proofs[0].len(), "proofs take the rest");

        let mc = MessageCollector::new();
        let proof = shard_bundle(0x11, 5, 0, 0);
        mc.add_message(1, proof.clone());
        for n in 0..30u8 {
            mc.add_message(2, vec![n; proof.len()]);
        }
        let copy = mc.snapshot_for_execution(2, budget, 100).unwrap();
        assert!(copy.contains(&proof), "the older proof rides");
        assert_eq!(copy.len(), 10, "other messages take the rest");
    }

    /// Over the budget, the shards whose proofs rode longest ago go first and
    /// those an executed ancestor carries go last, so every shard takes its
    /// turn instead of the same ones riding every frame.
    #[test]
    fn shard_proofs_over_the_budget_take_turns() {
        let mc = MessageCollector::new();
        let (verifier, _) = counting_verifier(|_| ShardFrameVerdict::Valid);
        mc.set_shard_frame_verifier(verifier);
        let all: HashSet<u8> = [0x11, 0x22, 0x33, 0x44].into();
        let size = shard_bundle(0x11, 5, 0, 0).len();
        let budget = 2 * size + size / 2;
        for &shard in &all {
            assert_eq!(mc.add_message_outcome(1, shard_bundle(shard, 5, 0, 0)), SubmitOutcome::Accepted);
        }
        let first = mc.snapshot_for_execution(1, budget, 100).unwrap();
        assert_eq!(shards_of(&first).len(), 2);
        mc.mark_finalized(&first);
        for &shard in &all {
            assert_eq!(mc.add_message_outcome(2, shard_bundle(shard, 6, 0, 0)), SubmitOutcome::Accepted);
        }
        let second = mc.snapshot_for_execution(2, budget, 100).unwrap();
        assert_eq!(shards_of(&second), &all - &shards_of(&first), "the shards left out go next");

        // `second` executed but not finalized: one of its shards has a newer
        // frame, which still waits behind the shards `first` carried.
        let carried = *shards_of(&second).iter().next().unwrap();
        assert_eq!(mc.add_message_outcome(3, shard_bundle(carried, 7, 0, 0)), SubmitOutcome::Accepted);
        let third: Vec<_> = mc
            .snapshot_for_proposal(3, budget, 100, None, &second)
            .unwrap()
            .into_iter()
            .map(|(data, _)| data)
            .collect();
        assert_eq!(shards_of(&third), shards_of(&first));
    }

    /// A proof the proposed frame cannot carry is not copied: its leader would
    /// drop it after it took budget.
    #[test]
    fn a_proposal_copies_no_proof_its_frame_cannot_carry() {
        let mc = MessageCollector::new();
        mc.add_message(1, shard_bundle(0x11, 5, 0, 0)); // anchored to GLOBAL frame 99
        assert_eq!(mc.snapshot_for_proposal(1, 4096, 100, Some(112), &[]).unwrap().len(), 1);
        assert!(mc.snapshot_for_proposal(1, 4096, 100, Some(113), &[]).unwrap().is_empty());
    }

    /// A shard's copied candidates are those its leader would examine: its
    /// highest verified frame and at most `MAX_TIP_VERIFICATIONS` unverified
    /// frames above it.
    #[test]
    fn a_proposal_copies_the_candidates_its_leader_would_examine() {
        let mc = MessageCollector::new();
        assert!(mc.add_verified_message(1, shard_bundle(0x11, 3, 0, 0)));
        for frame in 4..=8 {
            assert!(mc.add_message(1, shard_bundle(0x11, frame, 0, 0)));
        }
        let frames: HashSet<u64> = mc
            .snapshot_for_proposal(1, 1 << 20, 100, None, &[])
            .unwrap()
            .iter()
            .map(|(data, _)| extract_shard_frame_keys(data)[0].1)
            .collect();
        assert_eq!(frames, [8, 7, 6, 3].into());
    }

    /// Members' copies of one frame arrive together. A copy waits for the
    /// verdict on the first instead of taking a verification of its own: a
    /// valid first makes it a duplicate; an invalid first leaves it to be
    /// verified itself.
    #[test]
    fn copies_of_a_frame_under_verification_wait_for_its_verdict() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use std::sync::{mpsc, Arc, Mutex};
        for first_valid in [true, false] {
            let mc = Arc::new(MessageCollector::new());
            let (first, second) = (shard_bundle(0x11, 5, 0, 0), shard_bundle(0x11, 5, 1, 0));
            let calls = Arc::new(AtomicUsize::new(0));
            let (entered_tx, entered) = mpsc::channel::<()>();
            let (release, released) = mpsc::channel::<()>();
            let (entered_tx, released) = (Mutex::new(entered_tx), Mutex::new(released));
            let (counted, judged) = (calls.clone(), first.clone());
            mc.set_shard_frame_verifier(Arc::new(move |data: &[u8]| {
                counted.fetch_add(1, SeqCst);
                let _ = entered_tx.lock().unwrap().send(());
                let _ = released.lock().unwrap().recv();
                if data == judged.as_slice() && !first_valid {
                    ShardFrameVerdict::Invalid("forged".into())
                } else {
                    ShardFrameVerdict::Valid
                }
            }));
            let admit = |data: Vec<u8>| {
                let mc = mc.clone();
                std::thread::spawn(move || mc.add_message_outcome(3, data))
            };
            let a = admit(first.clone());
            entered.recv().unwrap();
            let b = admit(second.clone());
            std::thread::sleep(Duration::from_millis(200));
            assert_eq!(calls.load(SeqCst), 1, "the second copy waits instead of verifying");
            drop(release);
            if first_valid {
                assert_eq!(a.join().unwrap(), SubmitOutcome::Accepted);
                assert_eq!(b.join().unwrap(), SubmitOutcome::Duplicate);
                assert_eq!(calls.load(SeqCst), 1);
            } else {
                assert_eq!(a.join().unwrap(), SubmitOutcome::Filtered(Refusal::InvalidShardFrame));
                assert_eq!(b.join().unwrap(), SubmitOutcome::Accepted);
                assert_eq!(calls.load(SeqCst), 2);
            }
            assert!(mc.verifying.lock().unwrap().is_empty());
        }
    }

    /// With every verification slot taken (an epoch's first frame
    /// publishing slows each one), a frame is held unverified at once
    /// instead of refused: refused, it could outlive its GLOBAL window.
    #[test]
    fn a_frame_arriving_with_every_verification_busy_is_held_unverified() {
        use std::sync::{mpsc, Arc, Mutex};
        let mc = Arc::new(MessageCollector::new());
        let (entered_tx, entered) = mpsc::channel::<()>();
        let (release, released) = mpsc::channel::<()>();
        let (entered_tx, released) = (Mutex::new(entered_tx), Mutex::new(released));
        mc.set_shard_frame_verifier(Arc::new(move |_: &[u8]| {
            let _ = entered_tx.lock().unwrap().send(());
            let _ = released.lock().unwrap().recv();
            ShardFrameVerdict::Valid
        }));
        let busy: Vec<_> = (0..MAX_CONCURRENT_VERIFICATIONS as u8)
            .map(|shard| {
                let mc = mc.clone();
                let handle = std::thread::spawn(move || mc.add_message_outcome(1, shard_bundle(0x20 + shard, 5, 0, 0)));
                entered.recv().unwrap();
                handle
            })
            .collect();
        let late = shard_bundle(0x11, 5, 0, 0);
        assert_eq!(mc.add_message_outcome(1, late.clone()), SubmitOutcome::Accepted);
        assert!(!mc.is_verified(&late));
        drop(release);
        for handle in busy {
            assert_eq!(handle.join().unwrap(), SubmitOutcome::Accepted);
        }
        assert_eq!(mc.verifications.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// The shard index follows proofs that move between ranks.
    #[test]
    fn supersession_finds_proofs_moved_between_ranks() {
        let mc = MessageCollector::new();
        let (verifier, _) = counting_verifier(|_| ShardFrameVerdict::Valid);
        mc.set_shard_frame_verifier(verifier);
        assert_eq!(mc.add_message_outcome(3, shard_bundle(0x11, 5, 0, 0)), SubmitOutcome::Accepted);
        assert_eq!(mc.add_message_outcome(3, b"join".to_vec()), SubmitOutcome::Accepted);
        mc.rebase_ranks();
        assert!(mc.is_verified(&shard_bundle(0x11, 5, 0, 0)));
        assert_eq!(mc.add_message_outcome(1, shard_bundle(0x11, 6, 0, 0)), SubmitOutcome::Accepted);
        assert_eq!(mc.collect_for_rank(1), vec![b"join".to_vec(), shard_bundle(0x11, 6, 0, 0)]);
    }
}
