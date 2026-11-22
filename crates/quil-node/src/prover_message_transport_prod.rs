//! Production [`ProverMessageTransport`] impl.
//!
//! Fans bundle bytes out to every known archive over gRPC (mTLS via
//! the local Ed448 seed) and concurrently publishes the same bytes on
//! `GLOBAL_PROVER` via BlossomSub. Mirrors the previous inline logic
//! that lived in `ProverPipeline::publish_prover_message` before the
//! transport abstraction was introduced.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tracing::{debug, error, info, warn};

use quil_engine::prover_message_transport::ProverMessageTransport;
use quil_engine::storage_epoch_batch::ArchiveAnswer;
use quil_rpc::archive_client::{ArchiveClientError, SharedSubmitError};
use quil_rpc::{ArchiveClient, ArchiveEndpointPool};
use quil_types::error::{QuilError, Result};
use quil_types::proto::global::GlobalFrameHeader;
use quil_types::store::ClockStore;

const GLOBAL_PROVER_BITMASK: &[u8] = &[0x00, 0x00, 0x00];

/// Production transport: gRPC fan-out to archives, optionally also
/// BlossomSub publish.
pub struct ProdProverMessageTransport {
    pub archive_pool: Arc<ArchiveEndpointPool>,
    pub clock_store: Arc<dyn ClockStore>,
    pub p2p_handle: quil_p2p::node::P2PHandle,
    /// Ed448 seed for mTLS to archives. `None` when this node lacks an
    /// Ed448 identity (e.g. read-only client mode); in that case the
    /// gRPC fan-out is skipped and only BlossomSub carries the bundle.
    pub falcon_signing_key: Option<Vec<u8>>,
    /// When false, the BlossomSub publish on GLOBAL_PROVER is skipped
    /// and messages are sent exclusively via direct gRPC to archives.
    /// Non-archive nodes have no need to gossip prover messages — they
    /// don't subscribe to GLOBAL_PROVER either (matching Go).
    pub publish_to_blossomsub: bool,
    /// Submissions every archive refused only for now, resent later.
    pub(crate) retry_queue: Arc<SubmitRetryQueue>,
    /// The check an archive's head header must pass to set a join's frame:
    /// the archive-sync header check and a committee finalization
    /// certificate (`archive_sync::join_header_check`).
    pub(crate) join_header_check: quil_rpc::frame_sync::FrameValidator,
}

/// The header a join is stamped with, and its source: the freshest archive
/// head header that is not below the local head and passes `check`, else
/// the local head. No archive answer lowers the join frame below what this
/// node already holds (a replayed old certified head, frame 0, a legacy
/// header signed by a key it carries), and none raises it unverified.
fn join_frame_header(
    local: Option<GlobalFrameHeader>,
    answers: Vec<(String, GlobalFrameHeader)>,
    check: &quil_rpc::frame_sync::FrameValidator,
) -> Option<(String, GlobalFrameHeader)> {
    let floor = local.as_ref().map_or(0, |header| header.frame_number);
    let (current, stale): (Vec<_>, Vec<_>) = answers
        .into_iter()
        .partition(|(_, header)| header.frame_number >= floor);
    if let Some((addr, header)) = stale.first() {
        warn!(
            %addr,
            frame_number = header.frame_number,
            local_head = floor,
            below = stale.len(),
            scope = "peer",
            "archive head header below the local head: not used for the join frame"
        );
    }
    let verified = |header: &GlobalFrameHeader| {
        check(&quil_types::proto::global::GlobalFrame {
            header: Some(header.clone()),
            requests: Vec::new(),
        })
    };
    freshest_verified_header(current, verified)
        .or_else(|| local.map(|header| ("local head".to_string(), header)))
}

/// The freshest of `answers` (archive, head header) that `verified` accepts:
/// an unverified header, however fresh, never sets a join's frame. `None`
/// when no answer verifies.
fn freshest_verified_header(
    mut answers: Vec<(String, GlobalFrameHeader)>,
    verified: impl Fn(&GlobalFrameHeader) -> bool,
) -> Option<(String, GlobalFrameHeader)> {
    // Freshest first; among equals, the first to answer.
    answers.sort_by_key(|(_, header)| std::cmp::Reverse(header.frame_number));
    for (addr, header) in answers {
        if verified(&header) {
            return Some((addr, header));
        }
        warn!(
            %addr,
            frame_number = header.frame_number,
            scope = "peer",
            "archive head header failed verification: not used for the join frame"
        );
    }
    None
}

/// Submissions every archive refused only for now (a full mempool, or, from
/// archives of 2026-10-15, shard frames it could not verify yet), and storage
/// epoch proofs no archive took for any reason but a refusal for good (a
/// timeout, a failed connection), resent by one task per node. Each round
/// sends the queue oldest first and ends at the first message other than a
/// storage epoch proof that is still refused everywhere, so a stalled network
/// gets one submission per node per round rather than a resend of
/// everything, and an undelivered proof holds back no other message. A proof
/// goes to the archives one after another when sent again. Rounds
/// back off from 5 s to a minute. A message is given up after ten minutes, a
/// storage epoch proof once this node's GLOBAL frame reaches its window's
/// end, and either oldest first once the queue is full. An archive that
/// refused a proof for room rests ([`ArchiveRests`]). Until 2026-10-15 a
/// refused submission was simply dropped: during the 880,560 halt every
/// regular's reward proofs and seals were lost. Until 2026-10-30 a storage
/// epoch proof that timed out on every archive was dropped too, and GLOBAL
/// kicked its prover at its window's end although it had proved in time.
#[derive(Default)]
pub(crate) struct SubmitRetryQueue {
    pending: std::sync::Mutex<VecDeque<Queued>>,
    running: AtomicBool,
    ids: AtomicU64,
    /// What became of the storage epoch proofs of each window, summarized
    /// once it ends ([`SubmitRetryQueue::report_windows`]). Locked after
    /// `pending` when both are.
    tally: std::sync::Mutex<std::collections::BTreeMap<u64, WindowTally>>,
    /// Messages dropped from the full queue, logged at most once per
    /// [`RETRY_DROP_LOG_EVERY`]. Never locked with `pending` or `tally`
    /// held.
    drops: std::sync::Mutex<QueueDrops>,
    /// This node's view of GLOBAL's seat slots ([`SettledSeat`]); none in
    /// tests that need none.
    settled: Option<SettledSeat>,
    /// Lines on proofs holding a settled seat, per proof digest
    /// ([`SubmitRetryQueue::warn_settled`]). Locked after `pending` when
    /// both are.
    settled_lines: std::sync::Mutex<ArchiveRefusals>,
    /// The archives resting after a refusal for room, first sends and
    /// resends alike. Never locked with another lock held.
    rests: ArchiveRests,
}

/// The archives that refused this node's storage epoch proof for room (a
/// full rank or share of held proofs), each resting until a time: sent no
/// proof whose window ends no sooner than the one it refused, as it would
/// refuse that too. A proof due sooner still goes: an archive makes room
/// for it by dropping proofs due later. The share of held proofs is full
/// for most of an epoch at about 8 MiB carried a GLOBAL frame, one frame
/// about 18.5 s, and one sender's share holds about one proof: rounds 5 s
/// apart sent every queued proof to every archive, and four archives
/// refused about 130,000 sends an epoch each, against about 1,100 seats
/// (2026-11-21). The rests are read as each send starts: an archive is
/// sent past its refusal only the proofs already on their way to it.
#[derive(Default)]
struct ArchiveRests {
    rests: std::sync::Mutex<std::collections::HashMap<String, Rest>>,
}

/// An archive resting ([`ArchiveRests`]): until when, and the earliest
/// window end of the proofs it refused for room meanwhile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rest {
    until: Instant,
    window_end: u64,
}

impl ArchiveRests {
    /// How long `archive` still rests at `now` for a proof whose window ends
    /// at `window_end`; `None` when it is sent.
    fn rests(&self, archive: &str, window_end: u64, now: Instant) -> Option<Duration> {
        let rests = self.rests.lock().unwrap();
        rests
            .get(archive)
            .filter(|rest| rest.until > now && window_end >= rest.window_end)
            .map(|rest| rest.until - now)
    }

    /// `archive` refused a proof whose window ends at `window_end` for room
    /// at `now`: it rests `rest` from now.
    fn refused_room(&self, archive: &str, window_end: u64, now: Instant, rest: Duration) {
        let mut rests = self.rests.lock().unwrap();
        rests.retain(|_, rest| rest.until > now);
        let until = now + rest;
        rests
            .entry(archive.to_string())
            .and_modify(|rest| {
                rest.until = rest.until.max(until);
                rest.window_end = rest.window_end.min(window_end);
            })
            .or_insert(Rest { until, window_end });
    }
}

/// A storage epoch proof's send, skipping the archives resting for it
/// ([`ArchiveRests`]).
#[derive(Clone, Copy)]
struct Resting<'a> {
    rests: &'a ArchiveRests,
    /// The proof's window end ([`StorageProofSubmission::window_end`]).
    window_end: u64,
    /// How long an archive refusing it for room rests at least, before
    /// jitter ([`jittered_up`]).
    rest: Duration,
}

/// What this node's view of GLOBAL shows of `member`'s seat slot on a
/// shard for an epoch (`StorageSeatSlot`). GLOBAL refuses a proof whole
/// when one of its seats settles an epoch already settled, or too late, or
/// seals a registration already sealed.
pub(crate) type SettledSeat = Arc<dyn Fn(&[u8; 32], &[u8], u64) -> SlotState + Send + Sync>;

/// One seat slot in this node's view of GLOBAL ([`SettledSeat`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SlotState {
    /// No settlement goes any more: an epoch proof settled the epoch or its
    /// window ended (`StorageSeatSlot::open` false).
    pub(crate) closed: bool,
    /// An epoch proof sealed the registration (`StorageSeatSlot::sealed_at`).
    pub(crate) sealed: bool,
}

/// This node's view of GLOBAL's seat slots: the slots `registry` holds,
/// committed by GLOBAL; a slot it lacks or cannot read shows open and
/// unsealed, so the proof goes.
pub(crate) fn registry_slots(
    registry: Arc<dyn quil_types::consensus::ProverRegistry>,
) -> SettledSeat {
    Arc::new(move |member: &[u8; 32], shard: &[u8], epoch: u64| {
        match registry.get_storage_seat_slot(member, shard, epoch) {
            Ok(Some(slot)) => SlotState {
                closed: !slot.open,
                sealed: slot.sealed_at.is_some(),
            },
            _ => SlotState::default(),
        }
    })
}

impl SubmitRetryQueue {
    /// An empty queue reading seat slots through `settled`.
    pub(crate) fn reading_slots(settled: SettledSeat) -> Self {
        Self {
            settled: Some(settled),
            ..Default::default()
        }
    }

    /// The seats `proof` settles that this node's view shows closed
    /// already, `<shard>@<epoch>` each, and the registrations it seals that
    /// the view shows sealed, `<shard>@<epoch> sealed`: with any, GLOBAL
    /// refuses the whole proof (`storage_epoch_proof::check`), so it seals
    /// and settles none of its seats.
    fn settled_seats(&self, proof: &StorageProofSubmission) -> Vec<String> {
        let Some(slots) = &self.settled else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for (shard, epoch, seals, settles) in &proof.seats {
            if *settles && slots(&proof.member, shard.as_slice(), *epoch).closed {
                found.push(format!("{}@{epoch}", hex::encode(shard)));
            }
            // A seal part seals the registration two epochs on.
            let seal_epoch = epoch.saturating_add(2);
            if *seals && slots(&proof.member, shard.as_slice(), seal_epoch).sealed {
                found.push(format!("{}@{seal_epoch} sealed", hex::encode(shard)));
            }
        }
        found
    }

    /// Count `proof`, not sent or dropped from the retry queue for a
    /// settled seat ([`Self::settled_seats`]), in its window's tally.
    fn count_settled(&self, proof: &StorageProofSubmission) {
        self.tally(proof.window_end, |t| t.settled += 1);
    }

    /// Warn that `proof`, of `bytes` bytes digesting to `digest`
    /// ([`proof_digest`]), holds `settled` seats ([`Self::settled_seats`])
    /// and what this node did with it (`action`), at this node's GLOBAL
    /// frame `frame`: once per proof, then every [`ARCHIVE_REFUSAL_EVERY`]
    /// it comes again, with the times since.
    fn warn_settled(
        &self,
        proof: &StorageProofSubmission,
        (digest, bytes): (&str, usize),
        settled: &[String],
        frame: Option<u64>,
        action: &'static str,
    ) {
        let now = Instant::now();
        let due = {
            let mut lines = self.settled_lines.lock().unwrap();
            lines
                .archives
                .retain(|_, (logged, _)| now.duration_since(*logged) < SETTLED_LINES_KEPT);
            lines.note(now, digest)
        };
        let Some((times, secs)) = due else {
            return;
        };
        let (member, _, epochs) = proof.fields();
        let (window_end, frames_left, _) = proof.time_left(frame);
        let owed = proof.owed_beside(settled);
        warn!(member, digest, seats = proof.seats.len(), ?settled, ?owed, ?epochs, bytes,
            frame = %or_unknown(frame), window_end, %frames_left, action, times, secs,
            "storage epoch proof holds a seat this node's view shows settled or closed, or seals a registration it \
             shows sealed: GLOBAL refuses the whole proof (a duplicate or late), so it is not sent (again) and its \
             acceptance drops no other queued proof; the workers of its other seats (owed) send them again while \
             their slots show them owed, and one not taken by window_end is lost");
    }

    /// Drop the queued storage epoch proofs holding a seat this node's view
    /// shows settled ([`Self::settled_seats`]), each counted in its
    /// window's tally. A proof whose window is over at this node's GLOBAL
    /// frame (`frame`, read after the view) stays for [`expire`]: GLOBAL
    /// closes a slot no proof settled at that frame, and such a proof is
    /// undelivered, not settled. Each view read clones a registry slot, so
    /// it reads with `pending` unlocked, a publish never waiting on it; a
    /// proof replaced or delivered meanwhile is gone already.
    fn drop_settled(&self, timing: RetryTiming, frame: &dyn Fn() -> Option<u64>) {
        if self.settled.is_none() {
            return;
        }
        let queued: Vec<(u64, Instant, StorageProofSubmission)> = {
            let pending = self.pending.lock().unwrap();
            pending
                .iter()
                .filter_map(|queued| Some((queued.id, queued.queued, queued.proof.clone()?)))
                .collect()
        };
        let held: Vec<(u64, Instant, &StorageProofSubmission, Vec<String>)> = queued
            .iter()
            .filter_map(|(id, at, proof)| {
                let settled = self.settled_seats(proof);
                (!settled.is_empty()).then_some((*id, *at, proof, settled))
            })
            .collect();
        if held.is_empty() {
            return;
        }
        let frame = frame();
        let held: Vec<(u64, Vec<String>)> = held
            .into_iter()
            .filter(|(_, at, proof, _)| !window_over(proof, *at, timing, frame))
            .map(|(id, _, _, settled)| (id, settled))
            .collect();
        if held.is_empty() {
            return;
        }
        let dropped: Vec<(Queued, Vec<String>)> = {
            let mut pending = self.pending.lock().unwrap();
            held.into_iter()
                .filter_map(|(id, settled)| {
                    let index = pending.iter().position(|queued| queued.id == id)?;
                    Some((pending.remove(index)?, settled))
                })
                .collect()
        };
        for (queued, settled) in dropped {
            let Some(proof) = &queued.proof else {
                continue;
            };
            abandoned(proof, "settled");
            let digest = proof_digest(&queued.bytes);
            let sent = (digest.as_str(), queued.bytes.len());
            self.warn_settled(proof, sent, &settled, frame, "dropped from the retry queue");
            self.count_settled(proof);
        }
    }
}

/// Tell the node's storage epoch proof batching that this transport gave
/// `proof` up undelivered (`storage_epoch_batch::note_proof_abandoned`), so
/// its seats' retries go at once; `why` names the path. Every path that
/// removes a proof without an archive taking it calls this: GLOBAL refuses
/// it whole (`settled`), every archive refused it for good (`refused`), a
/// full queue dropped it (`evicted`). Not a window's end, after which no
/// retry lands, nor a proof a later one supersedes: that one was made only
/// once the stamps it shares lapsed, and as the seat lists may match,
/// giving the earlier up could take back the later one's.
fn abandoned(proof: &StorageProofSubmission, why: &'static str) {
    #[cfg(test)]
    abandoned_proofs()
        .lock()
        .unwrap()
        .push((why, proof.member, proof.seats.clone()));
    let (member, shards, epochs) = proof.fields();
    debug!(
        member,
        ?shards,
        ?epochs,
        why,
        "storage epoch proof given up undelivered: its seats' retries are proved at once"
    );
    quil_engine::storage_epoch_batch::note_proof_abandoned(&proof.member, &proof.seats);
}

/// A proof given up ([`abandoned`]): why, its member and its seats.
#[cfg(test)]
type AbandonedProof = (&'static str, [u8; 32], Vec<(Vec<u8>, u64, bool, bool)>);

/// Each proof given up ([`abandoned`]), so tests see each path call it.
#[cfg(test)]
fn abandoned_proofs() -> &'static std::sync::Mutex<Vec<AbandonedProof>> {
    static ABANDONED: std::sync::OnceLock<std::sync::Mutex<Vec<AbandonedProof>>> =
        std::sync::OnceLock::new();
    ABANDONED.get_or_init(Default::default)
}

/// How long a proof's last line on a settled seat is kept to bound the next
/// ([`SubmitRetryQueue::warn_settled`]).
const SETTLED_LINES_KEPT: Duration = Duration::from_secs(3600);

/// A submission's digest for log lines: the first 8 bytes of its SHA3-256,
/// in hex.
fn proof_digest(bytes: &[u8]) -> String {
    use sha3::Digest;
    hex::encode(&sha3::Sha3_256::digest(bytes)[..8])
}

/// What became of the storage epoch proofs whose window ends at one frame
/// (an epoch's settlements and the seals due with them).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct WindowTally {
    /// Proofs handed to this transport.
    published: u64,
    /// Of those, proofs whose seats all waited in the retry queue: they
    /// took the queued copy's place instead of being sent at once.
    folded: u64,
    /// Sends to the archives, first sends and resends.
    sent: u64,
    /// Sends an archive took.
    accepted: u64,
    /// Sends every archive refused for now (sent again).
    refused: u64,
    /// Sends every archive refused for good (not sent again).
    refused_for_good: u64,
    /// Proofs still queued when the window ended.
    undelivered: u64,
    /// Proofs a full retry queue dropped: a worker's later send of their
    /// seats may still deliver them, so they are not counted undelivered.
    dropped: u64,
    /// Proofs not sent, or dropped from the retry queue, as they held a
    /// seat this node's view showed settled, closed or sealed: GLOBAL
    /// refuses them whole.
    settled: u64,
}

/// Messages dropped from a full retry queue since the last line about them
/// ([`SubmitRetryQueue::log_drops`]).
#[derive(Default)]
struct QueueDrops {
    messages: u64,
    /// Of those, storage epoch proofs.
    proofs: u64,
    bytes: u64,
    /// When the last line was logged.
    logged: Option<Instant>,
}

/// One queued submission.
struct Queued {
    /// Its place in the queue: a later submission has a higher id.
    id: u64,
    bytes: Vec<u8>,
    queued: Instant,
    /// The storage epoch proof it carries.
    proof: Option<StorageProofSubmission>,
    /// Resends every archive failed.
    attempts: u32,
    /// When a failure to send it was last logged.
    logged: Instant,
}

#[derive(Clone, Copy)]
struct RetryTiming {
    first: Duration,
    longest: Duration,
    give_up: Duration,
    /// When a storage epoch proof is given up while this node knows no
    /// GLOBAL frame: its window ends at most two epochs after it began.
    proof_give_up: Duration,
    /// How often a storage epoch proof's failed resends are logged.
    proof_log_every: Duration,
    /// How long an archive refusing a storage epoch proof for room rests
    /// at least ([`ArchiveRests`]), before jitter adds up to half
    /// ([`jittered_up`]).
    room_rest: Duration,
}

const RETRY_TIMING: RetryTiming = RetryTiming {
    first: Duration::from_secs(5),
    longest: Duration::from_secs(60),
    give_up: Duration::from_secs(600),
    proof_give_up: Duration::from_secs(4 * 3600),
    proof_log_every: Duration::from_secs(300),
    // Over two GLOBAL frames at mainnet's pace (about 18.5 s each,
    // 2026-11-21), so a frame carrying held proofs frees the room; jitter
    // makes it 40-60 s.
    room_rest: Duration::from_secs(40),
};
const RETRY_MAX_MESSAGES: usize = 256;
const RETRY_MAX_BYTES: usize = 32 << 20;
/// How often messages dropped from a full retry queue are logged: the first
/// at once, then those of each interval in one line.
const RETRY_DROP_LOG_EVERY: Duration = Duration::from_secs(60);

impl SubmitRetryQueue {
    /// Queue `bytes` (once), in place of the queued storage epoch proofs it
    /// supersedes ([`StorageProofSubmission::supersedes`]); true if no
    /// worker is running and the caller must start one.
    fn push(&self, bytes: Vec<u8>) -> bool {
        let proof = StorageProofSubmission::of(&bytes);
        let mut pending = self.pending.lock().unwrap();
        if !pending.iter().any(|queued| queued.bytes == bytes) {
            if let Some(proof) = &proof {
                let (mut replaced, mut replaced_bytes) = (0usize, 0usize);
                pending.retain(|queued| {
                    let gone = queued
                        .proof
                        .as_ref()
                        .is_some_and(|old| proof.supersedes(old));
                    replaced += usize::from(gone);
                    replaced_bytes += if gone { queued.bytes.len() } else { 0 };
                    !gone
                });
                if replaced > 0 {
                    let (member, shards, epochs) = proof.fields();
                    info!(member, ?shards, ?epochs, bytes = bytes.len(), replaced, replaced_bytes,
                        "storage epoch proof queued in place of earlier proofs of the same settlements or seals: GLOBAL \
                         applies only the first of them to ride a frame, so the archives hold one copy");
                }
            }
            pending.push_back(Queued {
                id: self.ids.fetch_add(1, Ordering::Relaxed),
                bytes,
                queued: Instant::now(),
                proof,
                attempts: 0,
                // Its first failure was logged as it was queued.
                logged: Instant::now(),
            });
            let mut total: usize = pending.iter().map(|queued| queued.bytes.len()).sum();
            let mut dropped = Vec::new();
            while pending.len() > RETRY_MAX_MESSAGES || total > RETRY_MAX_BYTES {
                let Some(oldest) = pending.pop_front() else {
                    break;
                };
                total -= oldest.bytes.len();
                dropped.push(oldest);
            }
            let queued = (pending.len(), total);
            drop(pending);
            if !dropped.is_empty() {
                self.dropped(&dropped, queued);
            }
        } else {
            drop(pending);
        }
        !self.running.swap(true, Ordering::AcqRel)
    }

    /// Count the messages a full queue `dropped` (the storage epoch proofs
    /// among them in their window's tally) and log them
    /// ([`Self::log_drops`]); `queued` is what the queue still holds, in
    /// messages and bytes.
    fn dropped(&self, dropped: &[Queued], queued: (usize, usize)) {
        let mut proofs = 0u64;
        for proof in dropped.iter().filter_map(|queued| queued.proof.as_ref()) {
            proofs += 1;
            self.tally(proof.window_end, |t| t.dropped += 1);
        }
        let mut drops = self.drops.lock().unwrap();
        drops.messages += dropped.len() as u64;
        drops.proofs += proofs;
        drops.bytes += dropped
            .iter()
            .map(|queued| queued.bytes.len() as u64)
            .sum::<u64>();
        Self::log_drops(&mut drops, queued, false);
        drop(drops);
        for proof in dropped.iter().filter_map(|queued| queued.proof.as_ref()) {
            abandoned(proof, "evicted");
        }
    }

    /// One line for the messages dropped from the full queue since the last
    /// one: at the first drop, then at most once per
    /// [`RETRY_DROP_LOG_EVERY`] while drops continue, once more for any left
    /// unlogged when a round finds the interval over, and, with `flush`, at
    /// once for any left unlogged.
    fn log_drops(drops: &mut QueueDrops, (queued, queued_bytes): (usize, usize), flush: bool) {
        let early = drops
            .logged
            .is_some_and(|at| at.elapsed() < RETRY_DROP_LOG_EVERY);
        if drops.messages == 0 || (early && !flush) {
            return;
        }
        let secs = drops.logged.map(|at| at.elapsed().as_secs());
        warn!(dropped = drops.messages, proofs = drops.proofs, bytes = drops.bytes,
            since_secs = %or_unknown(secs), queued, queued_bytes,
            max_messages = RETRY_MAX_MESSAGES, max_bytes = RETRY_MAX_BYTES,
            "prover submission retry queue full: its oldest messages were dropped since the last such line \
             (since_secs unknown: the first). The archives refused or did not answer this node's submissions \
             for longer than the queue holds: see the 'storage epoch proof still not delivered' lines for their \
             reasons. A dropped storage epoch proof counts as dropped, not undelivered, in its window's summary: \
             a worker's later send of its seats may still deliver them");
        *drops = QueueDrops {
            logged: Some(Instant::now()),
            ..Default::default()
        };
    }

    /// Log the drops left unlogged once their interval is over, or with
    /// `flush` at once ([`Self::log_drops`]).
    fn report_drops(&self, flush: bool) {
        let queued = {
            let pending = self.pending.lock().unwrap();
            (
                pending.len(),
                pending.iter().map(|queued| queued.bytes.len()).sum(),
            )
        };
        Self::log_drops(&mut self.drops.lock().unwrap(), queued, flush);
    }

    /// Drop the queued storage epoch proofs `delivered` supersedes
    /// ([`StorageProofSubmission::supersedes`]), now that an archive took
    /// it; returns how many. None when it holds a seat this node's view
    /// shows settled ([`Self::settled_seats`]): GLOBAL refuses it whole.
    fn delivered(&self, delivered: &StorageProofSubmission) -> usize {
        if !self.settled_seats(delivered).is_empty() {
            return 0;
        }
        let mut pending = self.pending.lock().unwrap();
        let before = pending.len();
        pending.retain(|queued| {
            !queued
                .proof
                .as_ref()
                .is_some_and(|old| delivered.supersedes(old))
        });
        before - pending.len()
    }

    fn len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// Proofs of the window ending at `window_end` held back for a settled
    /// seat ([`WindowTally::settled`]).
    #[cfg(test)]
    fn settled_in(&self, window_end: u64) -> u64 {
        let tally = self.tally.lock().unwrap();
        tally.get(&window_end).map_or(0, |t| t.settled)
    }

    /// Proofs of the window ending at `window_end` undelivered
    /// ([`WindowTally::undelivered`]).
    #[cfg(test)]
    fn undelivered_in(&self, window_end: u64) -> u64 {
        let tally = self.tally.lock().unwrap();
        tally.get(&window_end).map_or(0, |t| t.undelivered)
    }

    /// Whether queued storage epoch proofs of `proof`'s member cover each of
    /// its seats: sent at once, it would go to the archives beside them.
    fn holds(&self, proof: &StorageProofSubmission) -> bool {
        let pending = self.pending.lock().unwrap();
        proof.seats.iter().all(|seat| {
            pending
                .iter()
                .filter_map(|queued| queued.proof.as_ref())
                .any(|queued| queued.member == proof.member && queued.covers_seat(seat))
        })
    }

    /// Count in the tally of the window ending at `window_end`.
    fn tally(&self, window_end: u64, count: impl FnOnce(&mut WindowTally)) {
        count(self.tally.lock().unwrap().entry(window_end).or_default());
    }

    /// Log, once, what became of the storage epoch proofs of each window
    /// that ended by `frame`, this node's latest GLOBAL frame.
    fn report_windows(&self, frame: Option<u64>) {
        let Some(frame) = frame else {
            return;
        };
        let ended: Vec<(u64, WindowTally)> = {
            let mut tally = self.tally.lock().unwrap();
            let open = tally.split_off(&frame.saturating_add(1));
            std::mem::replace(&mut *tally, open).into_iter().collect()
        };
        for (window_end, t) in ended {
            // A window ending at the start of epoch E + 2 settles epoch E.
            let epoch = (window_end / quil_types::consensus::epoch_length_frames().max(1))
                .saturating_sub(2);
            macro_rules! window_line {
                ($level:ident) => {
                    $level!(epoch, window_end, published = t.published, folded = t.folded,
                        sent = t.sent, accepted = t.accepted, refused = t.refused,
                        refused_for_good = t.refused_for_good, undelivered = t.undelivered,
                        dropped = t.dropped, settled = t.settled,
                        "storage epoch proofs of a window that ended: published by this node's workers (folded: sent again while \
                         the retry queue held their seats, so they went at its next round instead of at once), sends to the \
                         archives, sends an archive took, sends every archive refused for now or for good, proofs still \
                         undelivered when the window ended, proofs a full retry queue dropped, and proofs not sent or dropped \
                         as they held a seat this node's view showed settled, closed or sealed (GLOBAL refuses them whole). \
                         Settlement shows in each worker's 'storage settlement recorded' line; undelivered above 0 means \
                         GLOBAL withholds those seats' storage share; dropped above 0 that those seats settle only if a \
                         worker's later send of them landed (check that line); refused well above accepted that the \
                         archives' held proofs were full")
                };
            }
            if t.undelivered > 0 || t.dropped > 0 {
                window_line!(warn);
            } else {
                window_line!(info);
            }
        }
    }
}

/// `delay` less a random part of up to half of it, so nodes refused
/// together do not all send again together.
fn jittered(delay: Duration) -> Duration {
    delay - random_part(delay / 2)
}

/// `delay` plus a random part of up to half of it: [`jittered`] for a wait
/// that must last at least `delay`.
fn jittered_up(delay: Duration) -> Duration {
    delay + random_part(delay / 2)
}

/// A random duration of up to `most`.
fn random_part(most: Duration) -> Duration {
    use std::hash::BuildHasher;
    let spread = u64::try_from(most.as_nanos()).unwrap_or(u64::MAX);
    let draw = std::collections::hash_map::RandomState::new().hash_one(Instant::now());
    Duration::from_nanos(draw % spread.saturating_add(1))
}

/// The archives' answers to one submission.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Delivery {
    accepted: usize,
    /// Refusals that ask for a retry.
    retry: usize,
    /// Of those, refusals for room: a full rank or share of held proofs.
    room: usize,
    /// Every refusing archive's refusal, `<archive>: <reason>`, in the
    /// pool's order: at most one per archive ([`archive_name`]).
    refusals: Vec<String>,
    /// Of the refusals for room, archives not sent to as they rest
    /// ([`ArchiveRests`]).
    rested: usize,
}

impl Delivery {
    /// No archive was sent to: each was resting ([`ArchiveRests`]).
    fn unsent(&self) -> bool {
        self.rested > 0 && self.rested == self.refusals.len() && self.accepted == 0
    }
}

/// What `delivery` tells the node's storage epoch proof batching
/// (`storage_epoch_batch::note_archive_answer`): taken by an archive;
/// refused for room by every archive, with no send that may have landed (a
/// timeout) and no gossip publish that went out (`gossiped`); otherwise
/// unknown, which the batching counts as a send that may have landed.
fn proof_answer(delivery: &Delivery, gossiped: bool) -> ArchiveAnswer {
    if delivery.accepted > 0 {
        ArchiveAnswer::Taken
    } else if delivery.room > 0 && delivery.room == delivery.retry && !gossiped {
        ArchiveAnswer::RefusedForRoom
    } else {
        ArchiveAnswer::Unknown
    }
}

/// Tell the node's storage epoch proof batching what the archives answered
/// `proof` ([`proof_answer`]).
fn note_answer(proof: &StorageProofSubmission, delivery: &Delivery, gossiped: bool) {
    quil_engine::storage_epoch_batch::note_archive_answer(
        &proof.member,
        &proof.seats,
        proof_answer(delivery, gossiped),
    );
}

/// An archive refusal that asks for a retry: `RESOURCE_EXHAUSTED`, or an
/// archive from before 2026-10-15 refusing a full mempool as an invalid
/// argument.
fn retryable(error: &quil_rpc::archive_client::ArchiveClientError) -> bool {
    match error {
        quil_rpc::archive_client::ArchiveClientError::Rpc(status) => {
            status.code() == tonic::Code::ResourceExhausted
                || (status.code() == tonic::Code::InvalidArgument
                    && status.message().contains("rank buffer full"))
        }
        _ => false,
    }
}

/// A failure that tells nothing about the message: the request outran its
/// deadline, the connection failed or went away, or the archive was
/// unavailable.
fn transient(error: &ArchiveClientError) -> bool {
    match error {
        ArchiveClientError::Rpc(status) => {
            matches!(
                status.code(),
                tonic::Code::Cancelled | tonic::Code::DeadlineExceeded | tonic::Code::Unavailable
            ) || error.is_transport_failure()
        }
        ArchiveClientError::Transport(_) | ArchiveClientError::TlsInit(_) => true,
        ArchiveClientError::InvalidEndpoint(_)
        | ArchiveClientError::MissingField(_)
        | ArchiveClientError::Tls(_) => false,
    }
}

/// Whether a submission `error` failed is sent again: a refusal asking for a
/// retry, and for a storage epoch proof (`proof`), whose window lasts an
/// epoch, any transient failure too.
fn asks_for_retry(error: &ArchiveClientError, proof: bool) -> bool {
    retryable(error) || (proof && transient(error))
}

/// Resend the queue until it empties. A round sends the storage epoch proofs
/// whose window ends soonest first, then the other messages, each oldest
/// first, and ends at the first message other than a storage epoch proof
/// still refused for now everywhere. Rounds start a jittered back-off apart:
/// from `timing.first`, doubling after a round that ended at a message still
/// refused, up to `timing.longest`, each wait a random part of up to half
/// shorter ([`jittered`]). `frame` reads this node's latest GLOBAL frame, at
/// which a storage epoch proof's window ends.
async fn run_retries<F, Fut, G>(
    queue: Arc<SubmitRetryQueue>,
    timing: RetryTiming,
    submit: F,
    frame: G,
) where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Delivery>,
    G: Fn() -> Option<u64>,
{
    let mut delay = timing.first;
    loop {
        tokio::time::sleep(jittered(delay)).await;
        // Once a round: a proof settled while it ran goes at most once more,
        // and its acceptance drops no queued proof ([`resent`]).
        queue.drop_settled(timing, &frame);
        let mut sent = std::collections::HashSet::new();
        let mut failed = false;
        loop {
            let next = {
                let frame = frame();
                let mut pending = queue.pending.lock().unwrap();
                for window_end in expire(&mut pending, timing, frame) {
                    queue.tally(window_end, |t| t.undelivered += 1);
                }
                drop(pending);
                queue.report_windows(frame);
                queue.report_drops(false);
                let pending = queue.pending.lock().unwrap();
                pending
                    .iter()
                    .filter(|queued| !sent.contains(&queued.id))
                    .min_by_key(|queued| {
                        let window_end = queued.proof.as_ref().map(|proof| proof.window_end);
                        (window_end.unwrap_or(u64::MAX), queued.id)
                    })
                    .map(|queued| (queued.id, queued.bytes.clone()))
            };
            let Some((id, bytes)) = next else {
                if failed {
                    break;
                }
                // Stop, unless a message was queued while this one ended.
                queue.running.store(false, Ordering::Release);
                if queue.pending.lock().unwrap().is_empty()
                    || queue.running.swap(true, Ordering::AcqRel)
                {
                    // Drops left unlogged would wait for the next full queue.
                    queue.report_drops(true);
                    return;
                }
                continue;
            };
            let delivery = submit(bytes).await;
            sent.insert(id);
            match resent(&queue, id, &delivery, timing, &frame) {
                Resent::Done => delay = timing.first,
                Resent::ProofFailed => failed = true,
                Resent::Failed => break,
            }
        }
        // The round ended at a message still undelivered.
        delay = (delay * 2).min(timing.longest);
    }
}

/// How a resend went.
enum Resent {
    /// Delivered, refused for good or no longer queued.
    Done,
    /// A storage epoch proof stays queued.
    ProofFailed,
    /// Another message stays queued.
    Failed,
}

/// Record the outcome of resending queued submission `id`.
fn resent(
    queue: &SubmitRetryQueue,
    id: u64,
    delivery: &Delivery,
    timing: RetryTiming,
    frame: &dyn Fn() -> Option<u64>,
) -> Resent {
    let mut pending = queue.pending.lock().unwrap();
    // Gone: a later proof covering it replaced it, or was delivered.
    let Some(index) = pending.iter().position(|queued| queued.id == id) else {
        return Resent::Done;
    };
    // Not sent: every archive rests ([`ArchiveRests`]).
    if pending[index].proof.is_some() && delivery.unsent() {
        return Resent::ProofFailed;
    }
    if let Some(proof) = &pending[index].proof {
        note_answer(proof, delivery, false);
        queue.tally(proof.window_end, |t| {
            t.sent += 1;
            if delivery.accepted > 0 {
                t.accepted += 1;
            } else if delivery.retry > 0 {
                t.refused += 1;
            } else {
                t.refused_for_good += 1;
            }
        });
    }
    if delivery.accepted == 0 && delivery.retry > 0 {
        let queued = &mut pending[index];
        queued.attempts += 1;
        let Some(proof) = &queued.proof else {
            return Resent::Failed;
        };
        if queued.logged.elapsed() >= timing.proof_log_every {
            queued.logged = Instant::now();
            let (member, shards, epochs) = proof.fields();
            let (window_end, frames_left, mins_left) = proof.time_left(frame());
            warn!(member, ?shards, ?epochs, bytes = queued.bytes.len(), attempts = queued.attempts,
                secs = queued.queued.elapsed().as_secs(), refusals = %refusals(delivery),
                window_end, %frames_left, %mins_left, consequence = proof.consequence(),
                "storage epoch proof still not delivered: no archive took it in time; sending it again until its window ends");
        }
        return Resent::ProofFailed;
    }
    let queued = pending.remove(index).expect("present");
    let Some(proof) = &queued.proof else {
        if delivery.accepted == 0 {
            warn!("queued prover submission refused for good — dropping");
        }
        return Resent::Done;
    };
    let (member, shards, epochs) = proof.fields();
    if delivery.accepted == 0 {
        // A send that timed out may have landed after all.
        warn!(member, ?shards, ?epochs, bytes = queued.bytes.len(), attempts = queued.attempts + 1,
            refusals = %refusals(delivery),
            "storage epoch proof refused by every archive when sent again; an earlier send may have landed — not sent again");
        abandoned(proof, "refused");
        return Resent::Done;
    }
    // Holding a seat settled meanwhile, it seals and settles none.
    let settled = queue.settled_seats(proof);
    let before = pending.len();
    if settled.is_empty() {
        pending.retain(|other| {
            !other
                .proof
                .as_ref()
                .is_some_and(|old| proof.supersedes(old))
        });
    } else {
        abandoned(proof, "settled");
        let digest = proof_digest(&queued.bytes);
        let sent = (digest.as_str(), queued.bytes.len());
        queue.warn_settled(proof, sent, &settled, frame(), "taken by an archive");
    }
    let superseded = before - pending.len();
    drop(pending);
    let (window_end, frames_left, _) = proof.time_left(frame());
    info!(member, ?shards, ?epochs, bytes = queued.bytes.len(), accepted = delivery.accepted,
        attempts = queued.attempts + 1,
        secs = queued.queued.elapsed().as_secs(), window_end, %frames_left, superseded,
        "storage epoch proof delivered when sent again");
    Resent::Done
}

/// Whether the window of `proof`, queued at `queued`, is over: `frame`,
/// this node's latest GLOBAL frame, is at its end, or `timing.proof_give_up`
/// passed while none is known.
fn window_over(
    proof: &StorageProofSubmission,
    queued: Instant,
    timing: RetryTiming,
    frame: Option<u64>,
) -> bool {
    match frame {
        Some(frame) => frame >= proof.window_end,
        None => queued.elapsed() >= timing.proof_give_up,
    }
}

/// Drop what can no longer land: a message refused for `timing.give_up`, a
/// storage epoch proof once its window is over ([`window_over`]).
/// Returns the window ends of the storage epoch proofs dropped.
fn expire(pending: &mut VecDeque<Queued>, timing: RetryTiming, frame: Option<u64>) -> Vec<u64> {
    let mut given_up = 0;
    let mut undelivered = Vec::new();
    pending.retain(|queued| {
        let Some(proof) = &queued.proof else {
            let keep = queued.queued.elapsed() < timing.give_up;
            given_up += usize::from(!keep);
            return keep;
        };
        let closed = window_over(proof, queued.queued, timing, frame);
        if closed {
            let (member, shards, epochs) = proof.fields();
            error!(member, ?shards, ?epochs, bytes = queued.bytes.len(), window_end = proof.window_end,
                frame = %or_unknown(frame), attempts = queued.attempts + 1, secs = queued.queued.elapsed().as_secs(),
                consequence = proof.consequence(),
                "storage epoch proof undelivered when its window ended: no archive took it");
            undelivered.push(proof.window_end);
        }
        !closed
    });
    if given_up > 0 {
        warn!(
            given_up,
            "prover submissions still refused by every archive — giving up"
        );
    }
    undelivered
}

/// `value`, or "unknown".
fn or_unknown(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown".to_string(), |value| value.to_string())
}

/// A delivery's refusals, for log lines: every refusing archive with its
/// reason, `[<archive>: <reason>; ..]`, so a refusal all archives share
/// reads apart from one archive's.
fn refusals(delivery: &Delivery) -> String {
    if delivery.refusals.is_empty() {
        return "none".to_string();
    }
    format!("[{}]", delivery.refusals.join("; "))
}

/// The archive at `addr` as log lines name it, without its address: the
/// tail of the peer ID it is pinned to, else `unpinned#<place>`, `place`
/// counting from 1 in this node's archive list.
fn archive_name(addr: &str, place: usize) -> String {
    match quil_rpc::archive_client::pinned_archive_peer(addr) {
        Some(peer) => quil_rpc::diagnostics_service::peer_tail(&peer),
        None => format!("unpinned#{place}"),
    }
}

/// This node's latest GLOBAL frame.
fn latest_frame(clock_store: &dyn ClockStore) -> Option<u64> {
    clock_store
        .get_latest_global_clock_frame()
        .ok()?
        .header
        .map(|header| header.frame_number)
}

/// Submit `bytes` to every archive in `pool` over mTLS, each request allowed
/// a deadline for its size (`quil_rpc::archive_client::submit_deadline`).
#[cfg(test)]
async fn submit_to_archives(
    pool: &ArchiveEndpointPool,
    seed: Option<Vec<u8>>,
    bytes: Vec<u8>,
) -> (usize, Delivery) {
    submit_to_archives_with(pool, seed, bytes, false, None).await
}

/// [`submit_to_archives`]; `resending_proof` sends a storage epoch proof again
/// (see [`fan_out_to_archives`]), and `resting` skips the archives resting
/// for it ([`fan_out_resting`]). A storage epoch proof is sent again after
/// any transient failure, and when no archive is known yet.
async fn submit_to_archives_with(
    pool: &ArchiveEndpointPool,
    seed: Option<Vec<u8>>,
    bytes: Vec<u8>,
    resending_proof: bool,
    resting: Option<Resting<'_>>,
) -> (usize, Delivery) {
    let Some(seed) = seed else {
        return (0, Delivery::default());
    };
    let archive_addrs = pool.archives().await;
    let archives = archive_addrs.len();
    let proof = carries_storage_proof(&bytes);
    let submit = move |stream_addr: String, bytes: Vec<u8>| {
        let seed = seed.clone();
        async move {
            let dialing = Instant::now();
            // Over the connection this process shares with the archive: a
            // connection per submission let a burst from one address hit
            // the archive's per-source connection cap.
            match ArchiveClient::submit_shared(&stream_addr, &seed, bytes).await {
                Ok(()) => Ok(stream_addr),
                Err(SharedSubmitError::Submit(e)) => {
                    debug!(addr = %stream_addr, error = %e, "prover bundle submit rejected by archive");
                    let retry = asks_for_retry(&e, proof);
                    Err((
                        stream_addr,
                        format!("submit rejected: {}", refusal_reason(&e)),
                        retry,
                    ))
                }
                Err(SharedSubmitError::Dial(e)) => {
                    debug!(addr = %stream_addr, error = %e, "prover bundle submit: archive connect failed");
                    let retry = asks_for_retry(&e, proof);
                    Err((stream_addr, connect_failure(dialing.elapsed(), &*e), retry))
                }
            }
        }
    };
    let mut delivery =
        fan_out_resting(archive_addrs, bytes, submit, resending_proof, resting).await;
    if archives == 0 && proof {
        delivery.retry = 1;
        delivery.refusals = vec!["no archive known yet".to_string()];
    }
    (archives, delivery)
}

#[async_trait]
impl ProverMessageTransport for ProdProverMessageTransport {
    async fn latest_global_frame_header(&self) -> Result<GlobalFrameHeader> {
        // Prefer a live archive read so the join's frame_number tracks
        // the network head (Go rejects joins where
        // `frame_number < head - 10`). Fall back to local store only
        // if no archive is reachable.
        //
        // Hard timeout per archive: a stalled mTLS handshake or
        // unresponsive gRPC server on the first archive would otherwise
        // wedge `submit_join` forever, because nothing else in the
        // lifecycle pipeline imposes a deadline. Symptom observed in
        // the wild: `prover lifecycle action ProposeJoin {...}` logs,
        // then complete silence — the next info! ("building ProverJoin")
        // never fires because the await above never resolves, the
        // join cooldown never re-arms, and ProposeJoin is silently
        // dead for the rest of the session.
        // Query archives in parallel and take the FRESHEST response.
        // Archives drift a few frames apart due to gossip; if we use
        // the first-to-respond, we may stamp the join with a
        // frame_number that's already stale at the leading archive,
        // tripping Go's `frame_number + 10 < current_frame` check at
        // verify time. The freshness budget gets eaten by VDF compute
        // (~2s), gRPC delivery, and Go's collector queue depth, so
        // every frame of staleness at the source matters.
        //
        // VDF challenge is `sha3(header.output)` so we can't mix
        // outputs from different archives — we pick ONE complete
        // header, just the freshest one available.
        const PER_ARCHIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        const MAX_ARCHIVES_TO_TRY: usize = 5;
        let mut answers = Vec::new();
        if let Some(seed) = self.falcon_signing_key.clone() {
            let addrs: Vec<String> = self
                .archive_pool
                .archives()
                .await
                .into_iter()
                .take(MAX_ARCHIVES_TO_TRY)
                .collect();
            let mut handles = Vec::with_capacity(addrs.len());
            for addr in addrs {
                let seed_copy = seed.clone();
                let addr_for_log = addr.clone();
                handles.push(tokio::spawn(async move {
                    // The request's own deadline counts towards dropping a
                    // shared connection that answers nothing.
                    let deadline = tokio::time::Instant::now() + PER_ARCHIVE_TIMEOUT;
                    let attempt = async {
                        let Ok(mut c) = tokio::time::timeout_at(
                            deadline,
                            ArchiveClient::shared(&addr, &seed_copy),
                        )
                        .await?
                        else {
                            return Ok(None);
                        };
                        let fetched =
                            tokio::time::timeout_at(deadline, c.get_global_frame(0)).await;
                        match &fetched {
                            Ok(frame) => c.settle(
                                frame.as_ref().map(|_| ()),
                                quil_rpc::archive_client::SHARED_SHORT,
                            ),
                            Err(_) => c.deadline_passed(quil_rpc::archive_client::SHARED_SHORT),
                        }
                        Ok::<_, tokio::time::error::Elapsed>(fetched?.ok().and_then(|f| f.header))
                    };
                    match attempt.await {
                        Ok(Some(h)) => Some((addr_for_log, h)),
                        Ok(None) => {
                            tracing::debug!(
                                addr = %addr_for_log,
                                "archive returned no header"
                            );
                            None
                        }
                        Err(_) => {
                            tracing::warn!(
                                addr = %addr_for_log,
                                timeout_ms = PER_ARCHIVE_TIMEOUT.as_millis() as u64,
                                "archive frame-header fetch timed out",
                            );
                            None
                        }
                    }
                }));
            }
            for h in handles {
                if let Ok(Some(answer)) = h.await {
                    answers.push(answer);
                }
            }
        }
        let answered = answers.len();
        // Read after the archives answered, so the floor is the freshest
        // head this node holds.
        let local = self.clock_store.get_latest_global_clock_frame();
        let local_header = local.as_ref().ok().and_then(|frame| frame.header.clone());
        // A header any one archive (or whoever answers for it) serves
        // stamps the join, so it must verify as GLOBAL frames do, and it
        // never takes the join below the local head.
        match join_frame_header(local_header, answers, &self.join_header_check) {
            Some((source, header)) => {
                if self.falcon_signing_key.is_some() && source == "local head" {
                    tracing::warn!(
                        answered,
                        frame_number = header.frame_number,
                        "no archive head header verified above the local head — using the local head",
                    );
                }
                tracing::debug!(
                    %source,
                    frame_number = header.frame_number,
                    "selected the join frame header"
                );
                Ok(header)
            }
            None => match local {
                Err(e) => Err(QuilError::Internal(format!("no local frame: {e}"))),
                Ok(_) => Err(QuilError::Internal("local frame missing header".into())),
            },
        }
    }

    async fn publish_prover_bundle(&self, bundle_bytes: Vec<u8>) -> Result<()> {
        let started = Instant::now();
        let proof = StorageProofSubmission::of(&bundle_bytes);
        let bytes = bundle_bytes.len();
        if let Some(proof) = &proof {
            self.retry_queue
                .report_windows(latest_frame(self.clock_store.as_ref()));
            self.retry_queue
                .tally(proof.window_end, |t| t.published += 1);
            // GLOBAL refuses it whole: it would only take the archives' room.
            let settled = self.retry_queue.settled_seats(proof);
            if !settled.is_empty() {
                let digest = proof_digest(&bundle_bytes);
                self.retry_queue.warn_settled(
                    proof,
                    (&digest, bytes),
                    &settled,
                    latest_frame(self.clock_store.as_ref()),
                    "not sent",
                );
                self.retry_queue.count_settled(proof);
                abandoned(proof, "settled");
                return Ok(());
            }
            // GLOBAL refuses it whole: its window ended before it came.
            let frame = latest_frame(self.clock_store.as_ref());
            if let Some(frame) =
                frame.filter(|_| window_over(proof, Instant::now(), RETRY_TIMING, frame))
            {
                self.retry_queue
                    .tally(proof.window_end, |t| t.undelivered += 1);
                let (member, shards, epochs) = proof.fields();
                warn!(member, ?shards, ?epochs, bytes, window_end = proof.window_end, frame,
                    consequence = proof.consequence(),
                    "storage epoch proof not sent: its window ended before it was handed over (GLOBAL refuses it whole); \
                     check what held up its proving");
                return Ok(());
            }
            // A worker sends a seat's part again while no archive has taken
            // the last one (about every ten GLOBAL frames): with the queue
            // holding its seats, it takes the queued copy's place and goes
            // at the queue's next round, so each pending seat is sent once a
            // round instead of also at once to every archive.
            if self.retry_queue.holds(proof) {
                self.retry_queue.tally(proof.window_end, |t| t.folded += 1);
                if self.retry_queue.push(bundle_bytes) {
                    self.start_retries();
                }
                let (member, shards, epochs) = proof.fields();
                debug!(member, ?shards, ?epochs, bytes, queued = self.retry_queue.len(),
                    "storage epoch proof sent again while the retry queue holds its seats: it replaces the queued copy and goes at the queue's next round");
                return Ok(());
            }
        }
        // Fan out to archives concurrently. Each closure connects + submits
        // independently so a slow / unreachable archive does not block the
        // others.
        // A storage epoch proof skips the archives resting after refusing
        // one for room ([`ArchiveRests`]).
        let resting = proof.as_ref().map(|proof| Resting {
            rests: &self.retry_queue.rests,
            window_end: proof.window_end,
            rest: RETRY_TIMING.room_rest,
        });
        let grpc_future = submit_to_archives_with(
            &self.archive_pool,
            self.falcon_signing_key.clone(),
            bundle_bytes.clone(),
            false,
            resting,
        );

        // BlossomSub publish runs concurrently with the gRPC fan-out
        // when enabled. Non-archive nodes skip the gossip publish
        // because they don't subscribe to GLOBAL_PROVER — publishing
        // into a topic you haven't joined is wasteful and unreliable.
        // Archive nodes publish on both paths for maximum dissemination.
        let publish_bs = self.publish_to_blossomsub;
        let bs_handle = self.p2p_handle.clone();
        let bs_bytes = bundle_bytes.clone();
        let bs_future = async move {
            if !publish_bs {
                return Ok(());
            }
            bs_handle
                .publish(GLOBAL_PROVER_BITMASK.to_vec(), bs_bytes)
                .await
        };

        let ((archive_count, delivery), bs_result) = tokio::join!(grpc_future, bs_future);
        let grpc_ok_count = delivery.accepted;
        // Only an attempted BlossomSub publish counts as a delivery path;
        // disabled publishing must not turn archive rejection into success.
        if publish_bs {
            if let Err(ref e) = bs_result {
                warn!(error = %e, "BlossomSub publish failed for prover message");
            }
        }

        let outcome = combine_publish_outcome(
            archive_count,
            grpc_ok_count,
            publish_bs.then_some(&bs_result),
        );
        // Taken though settled meanwhile: GLOBAL refuses it whole.
        let taken_settled = match &proof {
            Some(proof) if grpc_ok_count > 0 => {
                let settled = self.retry_queue.settled_seats(proof);
                (!settled.is_empty()).then(|| (settled, proof_digest(&bundle_bytes)))
            }
            _ => None,
        };
        // Every archive refused it for now: resend it later.
        let queued = outcome.is_err() && delivery.retry > 0;
        if queued && self.retry_queue.push(bundle_bytes) {
            self.start_retries();
        }
        // No archive was sent to: each rests.
        let unsent = delivery.unsent();
        if let Some(proof) = &proof {
            note_answer(proof, &delivery, publish_bs && bs_result.is_ok());
            self.retry_queue.tally(proof.window_end, |t| {
                if unsent {
                    return;
                }
                t.sent += 1;
                if grpc_ok_count > 0 {
                    t.accepted += 1;
                } else if queued {
                    t.refused += 1;
                } else if outcome.is_err() {
                    t.refused_for_good += 1;
                }
            });
            let (member, shards, epochs) = proof.fields();
            let (window_end, frames_left, mins_left) =
                proof.time_left(latest_frame(self.clock_store.as_ref()));
            if grpc_ok_count > 0 {
                if let Some((settled, digest)) = &taken_settled {
                    abandoned(proof, "settled");
                    let frame = latest_frame(self.clock_store.as_ref());
                    let sent = (digest.as_str(), bytes);
                    self.retry_queue.warn_settled(
                        proof,
                        sent,
                        settled,
                        frame,
                        "taken by an archive",
                    );
                }
                let superseded = self.retry_queue.delivered(proof);
                info!(member, ?shards, ?epochs, bytes, accepted = grpc_ok_count, archives = archive_count,
                    secs = started.elapsed().as_secs_f64(), window_end, %frames_left, superseded,
                    "storage epoch proof delivered");
            } else if queued && unsent {
                info!(member, ?shards, ?epochs, bytes, archives = archive_count, refusals = %refusals(&delivery),
                    window_end, %frames_left, %mins_left, queued = self.retry_queue.len(),
                    "storage epoch proof queued unsent: every archive refused an earlier proof for room and rests; \
                     it goes at the retry queue's rounds, soonest window first");
            } else if queued {
                warn!(member, ?shards, ?epochs, bytes, archives = archive_count,
                    deadline_secs = quil_rpc::archive_client::submit_deadline(bytes).as_secs(),
                    refusals = %refusals(&delivery), window_end, %frames_left, %mins_left,
                    consequence = proof.consequence(),
                    "storage epoch proof not delivered: no archive took it in time; sending it again until its window ends");
            } else if outcome.is_err() {
                warn!(member, ?shards, ?epochs, bytes, archives = archive_count, refusals = %refusals(&delivery),
                    "storage epoch proof refused by every archive — not sent again");
                abandoned(proof, "refused");
            }
        }
        if archive_count > 0 && grpc_ok_count == 0 && proof.is_none() {
            if queued {
                warn!(
                    archive_count,
                    full = delivery.retry,
                    queued = self.retry_queue.len(),
                    "no archive accepted submission yet — queued to retry"
                );
            } else {
                warn!(
                    archive_count,
                    publish_bs, "no archive accepted submission — message likely dropped"
                );
            }
        }
        if archive_count == 0 && !publish_bs {
            warn!("no archives discovered AND BlossomSub publish disabled — prover message has no delivery path");
        }

        match outcome {
            Err(QuilError::P2p(message)) if queued => {
                Err(QuilError::P2p(format!("{message}; queued to retry")))
            }
            outcome => outcome,
        }
    }
}

impl ProdProverMessageTransport {
    /// Start the worker that resends the retry queue.
    fn start_retries(&self) {
        let (pool, seed) = (self.archive_pool.clone(), self.falcon_signing_key.clone());
        let clock_store = self.clock_store.clone();
        let queue = self.retry_queue.clone();
        tokio::spawn(run_retries(
            self.retry_queue.clone(),
            RETRY_TIMING,
            move |bytes| {
                let (pool, seed, queue) = (pool.clone(), seed.clone(), queue.clone());
                let resending_proof = carries_storage_proof(&bytes);
                let window_end = StorageProofSubmission::of(&bytes).map(|proof| proof.window_end);
                async move {
                    let resting = window_end.map(|window_end| Resting {
                        rests: &queue.rests,
                        window_end,
                        rest: RETRY_TIMING.room_rest,
                    });
                    submit_to_archives_with(&pool, seed, bytes, resending_proof, resting)
                        .await
                        .1
                }
            },
            move || latest_frame(clock_store.as_ref()),
        ));
    }
}

/// Report success if any archive accepted or an attempted BlossomSub publish
/// succeeded. A disabled BlossomSub path is not a failed publish.
fn combine_publish_outcome(
    archive_count: usize,
    archive_ok_count: usize,
    blossomsub_result: Option<&Result<()>>,
) -> Result<()> {
    if archive_ok_count > 0 || matches!(blossomsub_result, Some(Ok(()))) {
        return Ok(());
    }
    let archive_status = if archive_count == 0 {
        "no archives discovered"
    } else {
        "no archive accepted submission"
    };
    let blossomsub_status = match blossomsub_result {
        None => "BlossomSub publish disabled".to_string(),
        Some(Err(error)) => format!("BlossomSub publish failed: {error}"),
        Some(Ok(())) => unreachable!("successful publish returned above"),
    };
    Err(QuilError::P2p(format!(
        "publish_prover_bundle: {archive_status}; {blossomsub_status}"
    )))
}

/// Fan out a submission to every archive endpoint concurrently.
///
/// `submit` is a closure that takes a single `(stream_addr, payload)` and
/// returns `Ok(stream_addr)` on success or `Err((stream_addr, reason, retry))`.
/// Returns the successful submissions, the refusals asking for a retry and
/// every refusal.
///
/// `resending_proof` sends to one archive after another, still all of them:
/// concurrent uploads share this node's uplink, so a proof too large for that
/// to carry to every archive within its deadline would time out everywhere at
/// each resend, and an archive holds what it took for its own proposals only.
/// Its refusals log at debug: the resends' summary names them.
#[cfg(test)]
async fn fan_out_to_archives<F, Fut>(
    archive_addrs: Vec<String>,
    bundle_bytes: Vec<u8>,
    submit: F,
    resending_proof: bool,
) -> Delivery
where
    F: Fn(String, Vec<u8>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = std::result::Result<String, (String, String, bool)>>
        + Send
        + 'static,
{
    fan_out_resting(archive_addrs, bundle_bytes, submit, resending_proof, None).await
}

/// [`fan_out_to_archives`], a storage epoch proof skipping the archives
/// `resting` names resting for it and resting each that refuses it for room
/// ([`ArchiveRests`]). A skipped archive counts as a refusal for room.
async fn fan_out_resting<F, Fut>(
    archive_addrs: Vec<String>,
    bundle_bytes: Vec<u8>,
    submit: F,
    resending_proof: bool,
    resting: Option<Resting<'_>>,
) -> Delivery
where
    F: Fn(String, Vec<u8>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = std::result::Result<String, (String, String, bool)>>
        + Send
        + 'static,
{
    let mut handles = Vec::with_capacity(archive_addrs.len());
    let mut results = Vec::with_capacity(archive_addrs.len());
    let mut skipped = Vec::new();
    for (place, addr) in archive_addrs.into_iter().enumerate() {
        // Archive peer-info multiaddrs use the pubsub port (:8336);
        // the gRPC stream service listens on :8340.
        let stream_addr = crate::util::multiaddr::pubsub_to_stream_endpoint(&addr);
        if let Some(resting) = resting {
            if let Some(left) =
                resting
                    .rests
                    .rests(&stream_addr, resting.window_end, Instant::now())
            {
                skipped.push((place, stream_addr, left));
                continue;
            }
        }
        let bytes = bundle_bytes.clone();
        let submit = submit.clone();
        // Parallel fan-out: each handle's result is awaited below, so
        // panics surface as JoinError and per-archive failures are
        // logged individually. This is the correct use of bare spawn.
        let handle = tokio::spawn(async move { submit(stream_addr, bytes).await });
        if resending_proof {
            results.push((place, handle.await));
        } else {
            handles.push((place, handle));
        }
    }
    for (place, handle) in handles {
        results.push((place, handle.await));
    }
    let mut delivery = Delivery::default();
    let mut refused = Vec::new();
    let mut named = Vec::new();
    for (place, result) in results {
        match result {
            Ok(Ok(addr)) => {
                debug!(%addr, "prover message submitted via gRPC");
                delivery.accepted += 1;
            }
            Ok(Err((addr, reason, retry))) => {
                if retry {
                    delivery.retry += 1;
                    // The collector's refusal for room (`Refusal::RankFull`).
                    if reason.contains("rank buffer full") {
                        delivery.room += 1;
                        if let Some(resting) = resting {
                            let rest = jittered_up(resting.rest);
                            let now = Instant::now();
                            resting
                                .rests
                                .refused_room(&addr, resting.window_end, now, rest);
                        }
                    }
                }
                named.push((
                    place,
                    format!("{}: {reason}", archive_name(&addr, place + 1)),
                ));
                refused.push((addr, reason, retry));
            }
            Err(e) => {
                warn!(error = %e, "gRPC submit task join error");
            }
        }
    }
    for (place, addr, left) in skipped {
        delivery.retry += 1;
        delivery.room += 1;
        delivery.rested += 1;
        let archive = archive_name(&addr, place + 1);
        let secs = left.as_secs();
        named.push((
            place,
            format!("{archive}: not sent, resting {secs} s more after refusing an earlier proof for room"),
        ));
    }
    named.sort_by_key(|(place, _)| *place);
    delivery.refusals = named.into_iter().map(|(_, refusal)| refusal).collect();
    // A refusal another archive made up for loses nothing: summarize each
    // such archive at most every ARCHIVE_REFUSAL_EVERY, its reason naming
    // its state (a stale archive reports its executed frame against its
    // head). Without any acceptance, each refusal is a warning naming the
    // request.
    if !refused.is_empty() {
        let request = describe_bundle(&bundle_bytes);
        for (addr, reason, retry) in refused {
            if delivery.accepted == 0 {
                if resending_proof {
                    debug!(%addr, %reason, retry, %request, "gRPC submit failed");
                } else {
                    warn!(%addr, %reason, retry, %request, "gRPC submit failed");
                }
                continue;
            }
            let now = Instant::now();
            let summary = archive_refusals()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .note(now, &addr);
            if let Some((refusals, secs)) = summary {
                info!(
                    scope = "peer",
                    archive = %addr,
                    refusals,
                    secs,
                    %reason,
                    %request,
                    "an archive refused prover submissions another archive accepted"
                );
            }
        }
    }
    delivery
}

/// How often an archive's refusals of submissions another archive accepted
/// are summarized again.
const ARCHIVE_REFUSAL_EVERY: Duration = Duration::from_secs(600);

/// Refusals per archive since its last summary line.
#[derive(Debug, Default)]
struct ArchiveRefusals {
    archives: std::collections::HashMap<String, (Instant, u64)>,
}

impl ArchiveRefusals {
    /// Count one refusal by `archive`; returns the refusals and seconds
    /// since its last line when one is due (its first refusal at once).
    fn note(&mut self, now: Instant, archive: &str) -> Option<(u64, u64)> {
        let Some((logged, count)) = self.archives.get_mut(archive) else {
            self.archives.insert(archive.to_string(), (now, 0));
            return Some((1, 0));
        };
        *count += 1;
        let secs = now.duration_since(*logged);
        if secs < ARCHIVE_REFUSAL_EVERY {
            return None;
        }
        let refusals = std::mem::take(count);
        *logged = now;
        Some((refusals, secs.as_secs()))
    }
}

fn archive_refusals() -> &'static std::sync::Mutex<ArchiveRefusals> {
    static REFUSALS: std::sync::OnceLock<std::sync::Mutex<ArchiveRefusals>> =
        std::sync::OnceLock::new();
    REFUSALS.get_or_init(Default::default)
}

/// An archive's refusal without the transport's metadata: the gRPC code and
/// the archive's message.
/// Why a dial to an archive failed, for the line that names it: the time it
/// took and the causes beneath the error. A refusal at once (the archive's
/// connection cap or a closed port) reads apart from a handshake that ran to
/// its 10 s bound (this node starved of CPU, or the path), and a reset or a
/// rejected handshake names itself.
fn connect_failure(took: Duration, error: &(dyn std::error::Error + 'static)) -> String {
    let causes = quil_rpc::archive_client::error_chain(error);
    let took_ms = took.as_millis();
    if causes.is_empty() {
        format!("connect failed after {took_ms} ms: {error}")
    } else {
        format!("connect failed after {took_ms} ms: {error} ({causes})")
    }
}

fn refusal_reason(error: &quil_rpc::archive_client::ArchiveClientError) -> String {
    match error {
        quil_rpc::archive_client::ArchiveClientError::Rpc(status) => {
            format!("{:?}: {}", status.code(), status.message())
        }
        other => other.to_string(),
    }
}

/// What a bundle carries, for its failure lines: each request's type, and a
/// shard frame header's shard and frame (`frame header <filter>@<frame>`).
fn describe_bundle(bundle: &[u8]) -> String {
    use quil_execution::global_intrinsic::frame_header::{FrameHeader, TYPE_FRAME_HEADER};
    use quil_execution::message_envelope::CanonicalMessageBundle;
    let Ok(bundle) = CanonicalMessageBundle::from_canonical_bytes(bundle) else {
        return "undecodable bundle".to_string();
    };
    bundle
        .requests
        .iter()
        .flatten()
        .map(|request| match request.inner_type_prefix {
            TYPE_FRAME_HEADER => match FrameHeader::from_canonical_bytes(&request.inner_bytes) {
                Ok(header) => format!(
                    "frame header {}@{}",
                    hex::encode(&header.address),
                    header.frame_number
                ),
                Err(_) => "frame header".to_string(),
            },
            prefix => format!("request type {prefix:#06x}"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether `bundle` carries a storage epoch proof.
fn carries_storage_proof(bundle: &[u8]) -> bool {
    use quil_execution::global_intrinsic::storage_epoch_proof::TYPE_STORAGE_EPOCH_PROOF;
    use quil_execution::message_envelope::CanonicalMessageBundle;
    CanonicalMessageBundle::from_canonical_bytes(bundle).is_ok_and(|bundle| {
        bundle
            .requests
            .iter()
            .flatten()
            .any(|request| request.inner_type_prefix == TYPE_STORAGE_EPOCH_PROOF)
    })
}

/// The storage epoch proof a submission carries: its member, its seats and
/// the GLOBAL frame from which GLOBAL refuses it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct StorageProofSubmission {
    member: [u8; 32],
    /// Each seat's shard filter, the epoch it settles, and whether it seals
    /// (the registration two epochs on) and settles.
    seats: Vec<(Vec<u8>, u64, bool, bool)>,
    /// The end of its earliest seat's window: a settlement's window ends as
    /// the epoch after the next begins, and a seal's as the epoch it seals
    /// begins, the same frame (`storage_epoch_proof::check`).
    window_end: u64,
}

impl StorageProofSubmission {
    fn of(bundle: &[u8]) -> Option<Self> {
        use quil_execution::global_intrinsic::storage_epoch_proof::{
            StorageEpochProof, TYPE_STORAGE_EPOCH_PROOF,
        };
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        use quil_execution::message_envelope::CanonicalMessageBundle;
        let bundle = CanonicalMessageBundle::from_canonical_bytes(bundle).ok()?;
        let request = bundle
            .requests
            .iter()
            .flatten()
            .find(|request| request.inner_type_prefix == TYPE_STORAGE_EPOCH_PROOF)?;
        let proof = StorageEpochProof::from_canonical_bytes(&request.inner_bytes).ok()?;
        let window_end = proof
            .seats
            .iter()
            .flat_map(|seat| {
                let settles = seat.settles.then(|| settlement_window(seat.epoch).1);
                let seals = seat
                    .seals
                    .then(|| quil_types::consensus::epoch_start_frame(seat.seal_epoch()));
                settles.into_iter().chain(seals)
            })
            .min()?;
        Some(Self {
            member: proof.member,
            seats: proof
                .seats
                .iter()
                .map(|seat| {
                    (
                        seat.shard_filter.clone(),
                        seat.epoch,
                        seat.seals,
                        seat.settles,
                    )
                })
                .collect(),
            window_end,
        })
    }

    /// Whether `other` is needless once this is delivered: the same member,
    /// and each of its seats sealed or settled here for the same epoch.
    fn covers(&self, other: &Self) -> bool {
        self.member == other.member && other.seats.iter().all(|seat| self.covers_seat(seat))
    }

    /// Whether `other`, queued earlier, goes no more once this is queued or
    /// delivered: this covers it ([`Self::covers`]), or the same member
    /// settles a seat's epoch in both. GLOBAL refuses a proof whole when one
    /// of its seats settles an epoch already settled, so of two such proofs
    /// only the first to ride a frame applies, while both take the
    /// archives' held room: at the end of epoch 1493's window a node held
    /// three proofs settling one seat, resent alike, and none landed. The
    /// node's workers send again what else the earlier one carried, a seal
    /// on their retry timer and a settlement while its slot shows it owed.
    fn supersedes(&self, other: &Self) -> bool {
        let settles_too = |(shard, epoch, _, settles): &(Vec<u8>, u64, bool, bool)| {
            *settles
                && self
                    .seats
                    .iter()
                    .any(|(s, e, _, st)| *st && s == shard && e == epoch)
        };
        self.covers(other) || (self.member == other.member && other.seats.iter().any(settles_too))
    }

    /// Whether delivering this makes `seat` (shard, epoch, seals, settles)
    /// of the same member needless.
    fn covers_seat(&self, seat: &(Vec<u8>, u64, bool, bool)) -> bool {
        let (shard, epoch, seals, settles) = seat;
        self.seats
            .iter()
            .any(|(s, e, se, st)| s == shard && e == epoch && (*se || !seals) && (*st || !settles))
    }

    /// Its seats `settled` ([`SubmitRetryQueue::settled_seats`]) does not
    /// name, `<shard>@<epoch>` each: GLOBAL refusing the proof whole leaves
    /// them owed.
    fn owed_beside(&self, settled: &[String]) -> Vec<String> {
        self.seats
            .iter()
            .filter(|(shard, epoch, seals, settles)| {
                let shard = hex::encode(shard);
                let closed = *settles && settled.contains(&format!("{shard}@{epoch}"));
                let sealed = *seals
                    && settled.contains(&format!("{shard}@{} sealed", epoch.saturating_add(2)));
                !closed && !sealed
            })
            .map(|(shard, epoch, _, _)| format!("{}@{epoch}", hex::encode(shard)))
            .collect()
    }

    /// Its member, shards and epochs, for log lines.
    fn fields(&self) -> (String, Vec<String>, Vec<u64>) {
        let mut epochs: Vec<u64> = self.seats.iter().map(|seat| seat.1).collect();
        epochs.sort_unstable();
        epochs.dedup();
        (
            hex::encode(self.member),
            self.seats.iter().map(|seat| hex::encode(&seat.0)).collect(),
            epochs,
        )
    }

    /// Its window's end, and the frames and estimated minutes left at
    /// `frame`.
    fn time_left(&self, frame: Option<u64>) -> (u64, String, String) {
        let frames = frame.map(|frame| self.window_end.saturating_sub(frame));
        let mins = frames.map(|frames| {
            frames.saturating_mul(quil_types::consensus::ideal_frame_time_ms()) / 60_000
        });
        (self.window_end, or_unknown(frames), or_unknown(mins))
    }

    /// What follows if no archive takes it before its window ends.
    fn consequence(&self) -> &'static str {
        if self.seats.iter().any(|seat| seat.3) {
            "unless an archive takes it before the window ends, GLOBAL withholds this prover's storage share on these shards (before epoch 1342: kicks it)"
        } else {
            "unless an archive takes it before the window ends, the registrations it seals stay unsealed"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        asks_for_retry, combine_publish_outcome, describe_bundle, fan_out_resting,
        fan_out_to_archives, refusal_reason, refusals, retryable, run_retries, submit_to_archives,
        submit_to_archives_with, ArchiveRefusals, ArchiveRests, Delivery, Resting, RetryTiming,
        StorageProofSubmission, SubmitRetryQueue, ARCHIVE_REFUSAL_EVERY, RETRY_TIMING,
    };
    use quil_types::error::QuilError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    #[test]
    fn publish_errors_distinguish_skipped_and_failed_paths() {
        let disabled = combine_publish_outcome(7, 0, None).unwrap_err().to_string();
        assert!(disabled.contains("no archive accepted submission; BlossomSub publish disabled"));
        assert!(!disabled.contains("BlossomSub publish failed"));
        let absent = combine_publish_outcome(0, 0, None).unwrap_err().to_string();
        assert!(absent.contains("no archives discovered; BlossomSub publish disabled"));
        let failed = Err(QuilError::P2p("topic mesh unavailable".into()));
        let attempted = combine_publish_outcome(7, 0, Some(&failed))
            .unwrap_err()
            .to_string();
        assert!(attempted.contains("no archive accepted submission; BlossomSub publish failed:"));
        assert!(attempted.contains("topic mesh unavailable"));
        assert!(!attempted.contains("publish disabled"));
    }

    #[test]
    fn publish_success_still_requires_an_accepted_path() {
        let failed = Err(QuilError::P2p("topic mesh unavailable".into()));
        let succeeded = Ok(());
        assert!(combine_publish_outcome(7, 1, None).is_ok());
        assert!(combine_publish_outcome(7, 1, Some(&failed)).is_ok());
        assert!(combine_publish_outcome(0, 0, Some(&succeeded)).is_ok());
        assert!(combine_publish_outcome(7, 0, Some(&succeeded)).is_ok());
        assert!(combine_publish_outcome(7, 0, None).is_err());
        assert!(combine_publish_outcome(7, 0, Some(&failed)).is_err());
    }

    /// Verify that fan-out attempts every archive and counts every success.
    #[tokio::test]
    async fn publish_prover_message_fans_out_to_all_archives() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let submit = move |addr: String, _bytes: Vec<u8>| {
            let calls = calls_clone.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<String, (String, String, bool)>(addr)
            }
        };
        let addrs = vec![
            "1.2.3.4:8336".to_string(),
            "5.6.7.8:8336".to_string(),
            "9.10.11.12:8336".to_string(),
        ];
        let ok = fan_out_to_archives(addrs, vec![0xAA; 16], submit, false)
            .await
            .accepted;
        assert_eq!(ok, 3, "expected 3 successful submissions");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "expected 3 closure invocations (one per archive)"
        );
    }

    #[tokio::test]
    async fn publish_prover_message_falls_back_when_one_archive_fails() {
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            if addr.starts_with("5.") {
                Err::<String, (String, String, bool)>((addr, "simulated reject".to_string(), false))
            } else {
                Ok::<String, (String, String, bool)>(addr)
            }
        };
        let addrs = vec![
            "1.2.3.4:8336".to_string(),
            "5.6.7.8:8336".to_string(),
            "9.10.11.12:8336".to_string(),
        ];
        let ok = fan_out_to_archives(addrs, vec![], submit, false)
            .await
            .accepted;
        assert_eq!(ok, 2, "expected 2 successful, 1 failure");
    }

    #[tokio::test]
    async fn publish_prover_message_all_archives_fail() {
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            Err::<String, (String, String, bool)>((addr, "simulated reject".to_string(), false))
        };
        let addrs = vec!["1.2.3.4:8336".to_string()];
        let ok = fan_out_to_archives(addrs, vec![], submit, false)
            .await
            .accepted;
        assert_eq!(ok, 0, "expected 0 successful submissions");
    }

    #[tokio::test]
    async fn publish_prover_message_empty_archive_list() {
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            Ok::<String, (String, String, bool)>(addr)
        };
        let ok = fan_out_to_archives(vec![], vec![], submit, false).await;
        assert_eq!(
            ok,
            Delivery::default(),
            "expected 0 successful submissions with empty list"
        );
    }

    #[tokio::test]
    async fn fan_out_counts_refusals_that_ask_for_a_retry() {
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            match addr.as_str() {
                "a" => Ok::<String, (String, String, bool)>(addr),
                "b" => Err((addr, "rank buffer full".to_string(), true)),
                _ => Err((addr, "invalid".to_string(), false)),
            }
        };
        let delivery = fan_out_to_archives(
            vec!["a".into(), "b".into(), "c".into()],
            vec![],
            submit,
            false,
        )
        .await;
        assert_eq!(
            delivery,
            Delivery {
                accepted: 1,
                retry: 1,
                room: 1,
                refusals: vec![
                    "unpinned#2: rank buffer full".to_string(),
                    "unpinned#3: invalid".to_string(),
                ],
                rested: 0,
            }
        );
    }

    /// The node's batching hears of a proof as refused for room only when
    /// nothing else may have landed it: counted as refused, a timed-out
    /// send an archive took would keep a seat that fails GLOBAL in its
    /// peers' proofs. Anything else but a take is unknown, which the
    /// batching counts as a send that may have landed: a timeout, a refusal
    /// for good, no archive at all, or a gossip publish that went out.
    #[tokio::test]
    async fn only_a_refusal_for_room_everywhere_is_answered_as_one() {
        use quil_engine::storage_epoch_batch::ArchiveAnswer;
        let answered = |outcomes: &'static [&'static str]| async move {
            let submit = move |addr: String, _bytes: Vec<u8>| async move {
                let outcome = outcomes[addr.parse::<usize>().unwrap()];
                match outcome {
                    "ok" => Ok::<String, (String, String, bool)>(addr),
                    "full" => Err((addr, "submit rejected: rank buffer full".to_string(), true)),
                    "timeout" => Err((addr, "submit rejected: Timeout expired".to_string(), true)),
                    _ => Err((addr, "submit rejected: invalid".to_string(), false)),
                }
            };
            let addrs = (0..outcomes.len()).map(|i| i.to_string()).collect();
            fan_out_to_archives(addrs, vec![], submit, false).await
        };
        let full = answered(&["full", "full"]).await;
        println!("REACH i854 archive answers classed");
        assert_eq!(
            super::proof_answer(&full, false),
            ArchiveAnswer::RefusedForRoom,
            "room_unanswered: a proof every archive refused for room was not answered as one"
        );
        assert_eq!(
            super::proof_answer(&answered(&["full", "invalid"]).await, false),
            ArchiveAnswer::RefusedForRoom,
            "room_unanswered: a refusal for good beside one for room hid it"
        );
        assert_eq!(
            super::proof_answer(&answered(&["full", "timeout"]).await, false),
            ArchiveAnswer::Unknown,
            "timeout_as_room: a send that may have landed was answered as refused for room"
        );
        for outcomes in [&["invalid"][..], &[]] {
            assert_eq!(
                super::proof_answer(&answered(outcomes).await, false),
                ArchiveAnswer::Unknown,
                "unknown_as_room: {outcomes:?} was not answered as unknown"
            );
        }
        assert_eq!(
            super::proof_answer(&full, true),
            ArchiveAnswer::Unknown,
            "gossip_as_room: a proof gossiped beside refusals for room was answered as refused for room"
        );
        assert_eq!(
            super::proof_answer(&answered(&["full", "ok"]).await, false),
            ArchiveAnswer::Taken,
            "taken_unanswered: a proof an archive took was not answered as taken"
        );
    }

    /// When every archive refuses, the line names each with its reason, by
    /// its pinned peer and never its address, not only the first archive.
    #[tokio::test]
    async fn every_refusing_archive_is_named_by_its_pinned_peer() {
        let peer = || {
            quil_p2p::Keypair::falcon_from_bytes(&quil_p2p::generate_falcon_signing_key())
                .unwrap()
                .public()
                .to_peer_id()
        };
        let addrs: Vec<String> = (201..=204).map(|n| format!("192.0.2.{n}:8340")).collect();
        let mut tails = Vec::new();
        for addr in &addrs[..3] {
            let pinned = peer();
            quil_rpc::archive_client::pin_archive_peer(addr, pinned).unwrap();
            tails.push(quil_rpc::diagnostics_service::peer_tail(&pinned));
        }
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            let reason = if addr.ends_with("203:8340") {
                "connect failed after 10000 ms: timed out"
            } else {
                "rank buffer full"
            };
            Err::<String, (String, String, bool)>((addr, reason.to_string(), true))
        };
        let delivery = fan_out_to_archives(addrs, vec![], submit, true).await;
        assert_eq!((delivery.accepted, delivery.retry), (0, 4), "{delivery:?}");
        let line = refusals(&delivery);
        assert!(
            !line.contains("192.0.2."),
            "address_in_line: archives are named by peer, not address: {line}"
        );
        assert_eq!(
            delivery.refusals,
            vec![
                format!("{}: rank buffer full", tails[0]),
                format!("{}: rank buffer full", tails[1]),
                format!("{}: connect failed after 10000 ms: timed out", tails[2]),
                "unpinned#4: rank buffer full".to_string(),
            ],
            "each_archive_named: every refusing archive with its reason, in order"
        );
        assert_eq!(line, format!("[{}]", delivery.refusals.join("; ")));
        assert_eq!(refusals(&Delivery::default()), "none");
    }

    #[test]
    fn a_full_or_unverifiable_mempool_asks_for_a_retry() {
        use quil_rpc::archive_client::ArchiveClientError;
        let rpc = |status: tonic::Status| ArchiveClientError::Rpc(status);
        assert!(retryable(&rpc(tonic::Status::resource_exhausted(
            "submit rejected: shard frame verification unavailable"
        ))));
        // Archives from before the change refused a full mempool this way.
        assert!(retryable(&rpc(tonic::Status::invalid_argument(
            "submit rejected: message collector rejected: rank buffer full (rank 0, executed 0, head 880560)"
        ))));
        assert!(!retryable(&rpc(tonic::Status::invalid_argument(
            "submit rejected: shard frame failed verification"
        ))));
        assert!(!retryable(&ArchiveClientError::MissingField("data")));
    }

    const FAST: RetryTiming = RetryTiming {
        first: Duration::from_millis(5),
        longest: Duration::from_millis(20),
        give_up: Duration::from_secs(60),
        proof_give_up: Duration::from_secs(60),
        proof_log_every: Duration::from_secs(60),
        room_rest: Duration::from_secs(60),
    };

    #[tokio::test]
    async fn queued_submissions_are_resent_oldest_first_until_accepted() {
        let queue = Arc::new(SubmitRetryQueue::default());
        assert!(
            queue.push(b"one".to_vec()),
            "the first push starts the worker"
        );
        assert!(!queue.push(b"two".to_vec()));
        assert!(!queue.push(b"one".to_vec()), "queued once");
        assert_eq!(queue.len(), 2);
        let sent = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let log = sent.clone();
        run_retries(
            queue.clone(),
            FAST,
            move |bytes| {
                let log = log.clone();
                async move {
                    let mut log = log.lock().unwrap();
                    log.push(bytes);
                    // Archives are full for the first two rounds.
                    if log.len() <= 2 {
                        Delivery {
                            accepted: 0,
                            retry: 5,
                            ..Default::default()
                        }
                    } else {
                        Delivery {
                            accepted: 1,
                            ..Default::default()
                        }
                    }
                }
            },
            || None,
        )
        .await;
        let sent = sent.lock().unwrap().clone();
        assert_eq!(
            sent,
            vec![
                b"one".to_vec(),
                b"one".to_vec(),
                b"one".to_vec(),
                b"two".to_vec()
            ],
            "a round ends at the first message still refused"
        );
        assert_eq!(queue.len(), 0);
        assert!(
            queue.push(b"three".to_vec()),
            "an emptied queue's worker has stopped"
        );
    }

    #[tokio::test]
    async fn a_refusal_for_good_or_an_old_message_is_dropped() {
        let queue = Arc::new(SubmitRetryQueue::default());
        queue.push(b"invalid".to_vec());
        run_retries(
            queue.clone(),
            FAST,
            |_| async { Delivery::default() },
            || None,
        )
        .await;
        assert_eq!(queue.len(), 0);
        queue.push(b"stale".to_vec());
        let expired = RetryTiming {
            give_up: Duration::ZERO,
            ..FAST
        };
        run_retries(
            queue.clone(),
            expired,
            |_| async { unreachable!("an expired message is not sent") },
            || None,
        )
        .await;
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn failure_lines_name_the_request() {
        use quil_execution::global_intrinsic::frame_header::FrameHeader;
        let header = FrameHeader {
            address: vec![7; 4],
            frame_number: 9,
            ..Default::default()
        }
        .to_canonical_bytes()
        .unwrap();
        let bundle = crate::master_node::reward_proofs::prover_bundle(header).unwrap();
        assert_eq!(describe_bundle(&bundle), "frame header 07070707@9");
        let mut join = quil_execution::global_intrinsic::TYPE_PROVER_JOIN
            .to_be_bytes()
            .to_vec();
        join.extend_from_slice(b"join");
        let bundle = crate::master_node::reward_proofs::prover_bundle(join).unwrap();
        assert_eq!(
            describe_bundle(&bundle),
            format!(
                "request type {:#06x}",
                quil_execution::global_intrinsic::TYPE_PROVER_JOIN
            )
        );
        assert_eq!(describe_bundle(b"junk"), "undecodable bundle");
        let refused = quil_rpc::archive_client::ArchiveClientError::Rpc(
            tonic::Status::invalid_argument("rank buffer full"),
        );
        assert_eq!(
            refusal_reason(&refused),
            "InvalidArgument: rank buffer full"
        );
    }

    #[test]
    fn an_archive_refusing_what_another_accepted_is_summarized_every_interval() {
        let mut refusals = ArchiveRefusals::default();
        let t = std::time::Instant::now();
        assert_eq!(
            refusals.note(t, "a:8340"),
            Some((1, 0)),
            "its first refusal logs at once"
        );
        for n in 1..=5 {
            assert_eq!(refusals.note(t + Duration::from_secs(n), "a:8340"), None);
        }
        assert_eq!(
            refusals.note(t + Duration::from_secs(2), "b:8340"),
            Some((1, 0)),
            "archives are counted apart"
        );
        assert_eq!(
            refusals.note(t + ARCHIVE_REFUSAL_EVERY, "a:8340"),
            Some((6, 600))
        );
        assert_eq!(
            refusals.note(t + ARCHIVE_REFUSAL_EVERY + Duration::from_secs(1), "a:8340"),
            None
        );
    }

    /// A bundle of one storage epoch proof by `member` for `shard`: settling
    /// `epoch` and/or sealing its registration two epochs on, with a proof
    /// of `proof_bytes` bytes.
    fn storage_proof_bundle(
        member: u8,
        seats: &[(u8, u64, bool, bool)],
        proof_bytes: usize,
    ) -> Vec<u8> {
        use quil_execution::global_intrinsic::storage_epoch_proof::{SeatProof, StorageEpochProof};
        let proof = StorageEpochProof {
            member: [member; 32],
            seats: seats
                .iter()
                .map(|&(shard, epoch, seals, settles)| SeatProof {
                    shard_filter: vec![shard; 35],
                    epoch,
                    seals,
                    settles,
                    ..Default::default()
                })
                .collect(),
            proof: vec![0x5a; proof_bytes],
        };
        crate::master_node::reward_proofs::prover_bundle(proof.to_canonical_bytes()).unwrap()
    }

    /// An archive's peer listener (a PQNoise handshake, then `GlobalService`)
    /// taking every submission, behind a link that carries at most `rate`
    /// bytes a second toward it. Returns the link's address and the count of
    /// submissions the archive took.
    async fn archive_behind_slow_link(rate: usize) -> (String, Arc<AtomicUsize>) {
        archive_behind_link(Default::default(), rate).await
    }

    /// When a link is free next, for archives sharing it.
    type Link = Arc<std::sync::Mutex<Option<tokio::time::Instant>>>;

    /// [`archive_behind_slow_link`], over `link`, which other archives share.
    async fn archive_behind_link(link: Link, rate: usize) -> (String, Arc<AtomicUsize>) {
        use quil_types::proto::global::global_service_server::GlobalServiceServer;
        use quil_types::proto::global::GlobalFrame;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        struct NoFrames;
        impl quil_rpc::FrameLookup for NoFrames {
            fn get_latest_frame(&self) -> Result<GlobalFrame, String> {
                Err("no frames".into())
            }
            fn get_frame(&self, _frame_number: u64) -> Result<GlobalFrame, String> {
                Err("no frames".into())
            }
        }
        let taken = Arc::new(AtomicUsize::new(0));
        let handler: quil_rpc::SubmitHandler = {
            let taken = taken.clone();
            Arc::new(move |_request| {
                taken.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            })
        };
        let server_key = quil_p2p::generate_falcon_signing_key();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let archive = listener.local_addr().unwrap();
        let (streams_tx, streams) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (key, streams_tx) = (server_key.clone(), streams_tx.clone());
                tokio::spawn(async move {
                    if let Ok(stream) =
                        quil_rpc::pqnoise_channel::pq_server_handshake(tcp, &key).await
                    {
                        let _ = streams_tx.send(Ok::<_, std::io::Error>(stream));
                    }
                });
            }
        });
        let incoming = futures::stream::unfold(streams, |mut streams| async move {
            streams.recv().await.map(|stream| (stream, streams))
        });
        let service = GlobalServiceServer::new(
            quil_rpc::GlobalRpcServer::new(Arc::new(NoFrames)).with_submit_handler(handler),
        )
        .max_decoding_message_size(64 << 20);
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(incoming),
        );
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = front.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (client, _) = front.accept().await.unwrap();
                let link = link.clone();
                tokio::spawn(async move {
                    let Ok(upstream) = TcpStream::connect(archive).await else {
                        return;
                    };
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut upstream_read, mut upstream_write) = upstream.into_split();
                    tokio::spawn(async move {
                        let _ = tokio::io::copy(&mut upstream_read, &mut client_write).await;
                    });
                    let mut buffer = vec![0u8; 1024];
                    loop {
                        let n = match client_read.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if upstream_write.write_all(&buffer[..n]).await.is_err() {
                            break;
                        }
                        let free = {
                            let mut free = link.lock().unwrap();
                            let now = tokio::time::Instant::now();
                            let next = free.map_or(now, |free| free.max(now))
                                + Duration::from_secs_f64(n as f64 / rate as f64);
                            *free = Some(next);
                            next
                        };
                        tokio::time::sleep_until(free).await;
                    }
                    let _ = upstream_write.shutdown().await;
                });
            }
        });
        (address, taken)
    }

    /// An archive's counts: connections its listener accepted, submissions it
    /// took, and the most it held at once.
    #[derive(Clone, Default)]
    struct Counts {
        accepted: Arc<AtomicUsize>,
        taken: Arc<AtomicUsize>,
        peak: Arc<AtomicUsize>,
    }

    /// An archive's peer listener (a PQNoise handshake, then `GlobalService`)
    /// that holds each submission for `delay` before taking it. Returns its
    /// address and [`Counts`].
    async fn counting_archive(delay: Duration) -> (String, Counts) {
        use quil_types::proto::global::global_service_server::GlobalServiceServer;
        use quil_types::proto::global::GlobalFrame;
        use tokio::net::TcpListener;
        struct NoFrames;
        impl quil_rpc::FrameLookup for NoFrames {
            fn get_latest_frame(&self) -> Result<GlobalFrame, String> {
                Err("no frames".into())
            }
            fn get_frame(&self, _frame_number: u64) -> Result<GlobalFrame, String> {
                Err("no frames".into())
            }
        }
        let counts = Counts::default();
        let holding = Arc::new(AtomicUsize::new(0));
        let handler: quil_rpc::SubmitHandler = {
            let counts = counts.clone();
            Arc::new(move |_request| {
                let (counts, holding) = (counts.clone(), holding.clone());
                Box::pin(async move {
                    let held = holding.fetch_add(1, Ordering::SeqCst) + 1;
                    counts.peak.fetch_max(held, Ordering::SeqCst);
                    tokio::time::sleep(delay).await;
                    holding.fetch_sub(1, Ordering::SeqCst);
                    counts.taken.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            })
        };
        let server_key = quil_p2p::generate_falcon_signing_key();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (streams_tx, streams) = tokio::sync::mpsc::unbounded_channel();
        let accepted = counts.accepted.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                accepted.fetch_add(1, Ordering::SeqCst);
                let (key, streams_tx) = (server_key.clone(), streams_tx.clone());
                tokio::spawn(async move {
                    if let Ok(stream) =
                        quil_rpc::pqnoise_channel::pq_server_handshake(tcp, &key).await
                    {
                        let _ = streams_tx.send(Ok::<_, std::io::Error>(stream));
                    }
                });
            }
        });
        let incoming = futures::stream::unfold(streams, |mut streams| async move {
            streams.recv().await.map(|stream| (stream, streams))
        });
        let service = GlobalServiceServer::new(
            quil_rpc::GlobalRpcServer::new(Arc::new(NoFrames)).with_submit_handler(handler),
        )
        .max_decoding_message_size(64 << 20);
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(incoming),
        );
        (address, counts)
    }

    /// Two hundred submissions at once to an archive that holds each for
    /// two seconds all reach it over one connection, at most 64 (the bound
    /// per shared connection) at a time. Each used to dial a connection of
    /// its own, so bursts from nodes behind one address held hundreds of
    /// connections to every archive and its listener refused that address
    /// at its per-source cap.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn submissions_at_once_share_one_connection_to_an_archive() {
        let (address, counts) = counting_archive(Duration::from_secs(2)).await;
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(Duration::ZERO));
        pool.add(address).await;
        let key = quil_p2p::generate_falcon_signing_key();
        let submissions = (0..200u32).map(|n| {
            let (pool, key) = (pool.clone(), key.clone());
            tokio::spawn(async move {
                submit_to_archives(&pool, Some(key), n.to_be_bytes().repeat(16))
                    .await
                    .1
            })
        });
        let deliveries: Vec<Delivery> = futures::future::join_all(submissions)
            .await
            .into_iter()
            .map(Result::unwrap)
            .collect();
        let accepted = counts.accepted.load(Ordering::SeqCst);
        assert!(
            accepted <= 2,
            "connections accepted for 200 submissions at once: {accepted}"
        );
        let undelivered: Vec<&Delivery> = deliveries.iter().filter(|d| d.accepted != 1).collect();
        assert!(
            undelivered.is_empty(),
            "{} of 200 submissions not delivered, first {:?}",
            undelivered.len(),
            undelivered.first()
        );
        assert_eq!(counts.taken.load(Ordering::SeqCst), 200);
        let peak = counts.peak.load(Ordering::SeqCst);
        assert!(
            peak <= 64,
            "submissions in flight at once on one connection: {peak}"
        );
    }

    /// A submission over 32 KiB takes a connection of its own beside the one
    /// smaller submissions share, so a storage epoch proof never holds a
    /// frame header back in one connection's flow-control window; later
    /// submissions of either size ride those two.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_large_submission_takes_its_own_connection_beside_small_ones() {
        let (address, counts) = counting_archive(Duration::ZERO).await;
        let pool = quil_rpc::ArchiveEndpointPool::new(Duration::ZERO);
        pool.add(address).await;
        let key = quil_p2p::generate_falcon_signing_key();
        let (small, large) = (vec![1u8; 64], vec![2u8; 64 << 10]);
        for bytes in [small.clone(), large.clone(), small, large] {
            let (_, delivery) = submit_to_archives(&pool, Some(key.clone()), bytes).await;
            assert_eq!(delivery.accepted, 1, "{delivery:?}");
        }
        assert_eq!(
            counts.accepted.load(Ordering::SeqCst),
            2,
            "connections for small and large submissions"
        );
    }

    /// A 600 KB storage epoch proof sent over a link of 32 KiB/s takes about
    /// 19 s. A fixed 15 s request deadline cut it off on every archive
    /// (`Cancelled: Timeout expired`), and the proof was dropped; the
    /// deadline for its size lets it through.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_large_storage_proof_reaches_an_archive_over_a_slow_uplink() {
        let (address, taken) = archive_behind_slow_link(32 << 10).await;
        let pool = quil_rpc::ArchiveEndpointPool::new(Duration::ZERO);
        pool.add(address).await;
        let bundle = storage_proof_bundle(1, &[(7, 1335, false, true)], 600_000);
        let started = std::time::Instant::now();
        let (archives, delivery) =
            submit_to_archives(&pool, Some(quil_p2p::generate_falcon_signing_key()), bundle).await;
        let secs = started.elapsed().as_secs_f64();
        assert_eq!(archives, 1);
        assert_eq!(
            delivery.accepted, 1,
            "a 600 KB storage epoch proof over a 32 KiB/s link reached no archive \
             after {secs:.1} s: {delivery:?}"
        );
        assert_eq!(taken.load(Ordering::SeqCst), 1);
        assert!(secs > 15.0, "the link was not slow: {secs:.1} s");
    }

    /// Four archives share an uplink too slow to carry a 200 KB storage epoch
    /// proof to all of them within its deadline at once (25 s against 21 s):
    /// every upload times out, and would at each identical resend. Sent to
    /// one after another, each upload has the link to itself, and all four
    /// take it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_resent_storage_proof_reaches_every_archive_over_a_link_too_slow_for_all_at_once() {
        let link = Link::default();
        let pool = quil_rpc::ArchiveEndpointPool::new(Duration::ZERO);
        let mut taken = Vec::new();
        for _ in 0..4 {
            let (address, archive_took) = archive_behind_link(link.clone(), 32 << 10).await;
            pool.add(address).await;
            taken.push(archive_took);
        }
        let key = quil_p2p::generate_falcon_signing_key();
        let bundle = storage_proof_bundle(1, &[(7, 1335, false, true)], 200 * 1024);
        let (_, first) = submit_to_archives(&pool, Some(key.clone()), bundle.clone()).await;
        assert_eq!(
            (first.accepted, first.retry),
            (0, 4),
            "the first send, to all at once, times out everywhere: {first:?}"
        );
        let (_, resent) = submit_to_archives_with(&pool, Some(key), bundle, true, None).await;
        assert_eq!(
            resent.accepted, 4,
            "the resend, to one after another, reaches every archive: {resent:?}"
        );
        // An upload that timed out may still land from the socket buffers, so
        // an archive may see it twice; its collector answers a duplicate as
        // delivered.
        for archive_took in taken {
            assert!(archive_took.load(Ordering::SeqCst) >= 1);
        }
    }

    /// A storage epoch proof that every archive failed to take for a reason
    /// unrelated to it (a timeout, a failed connection) is sent again; other
    /// messages, and a refusal of the proof for good, are not.
    #[test]
    fn a_storage_proof_is_sent_again_after_a_timeout_or_a_failed_connection() {
        use quil_rpc::archive_client::ArchiveClientError;
        let timeout = ArchiveClientError::Rpc(tonic::Status::cancelled("Timeout expired"));
        let unavailable = ArchiveClientError::Rpc(tonic::Status::unavailable("connection reset"));
        let invalid = ArchiveClientError::Rpc(tonic::Status::invalid_argument(
            "submit rejected: epoch 1335 has nothing to settle",
        ));
        assert!(asks_for_retry(&timeout, true));
        assert!(asks_for_retry(&unavailable, true));
        assert!(!asks_for_retry(&invalid, true));
        assert!(!asks_for_retry(&timeout, false), "other messages as before");
        assert!(!asks_for_retry(&unavailable, false));
        let full = ArchiveClientError::Rpc(tonic::Status::resource_exhausted("full"));
        assert!(asks_for_retry(&full, false) && asks_for_retry(&full, true));
    }

    #[derive(Debug)]
    struct Outer(std::io::Error);
    impl std::fmt::Display for Outer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "transport error")
        }
    }
    impl std::error::Error for Outer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    /// The reason of a failed dial carries the time to the failure and the
    /// causes beneath the error, which "transport error" alone hides.
    #[test]
    fn a_failed_dial_names_its_time_and_its_cause() {
        let error = Outer(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection reset by peer",
        ));
        let reason = super::connect_failure(Duration::from_millis(10_004), &error);
        assert_eq!(
            reason,
            "connect failed after 10004 ms: transport error (connection reset by peer)"
        );
        let bare =
            super::connect_failure(Duration::from_millis(3), &std::io::Error::other("no route"));
        assert_eq!(bare, "connect failed after 3 ms: no route");
    }

    /// Over the real transport: an archive refusing connections leaves a
    /// storage epoch proof queued to retry, and any other message not.
    #[tokio::test]
    async fn an_unreachable_archive_queues_a_storage_proof_to_retry() {
        // A bound socket that never listens: a dial is refused, and no other
        // socket can take the port while the test dials it.
        let closed = tokio::net::TcpSocket::new_v4().unwrap();
        closed.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let address = closed.local_addr().unwrap().to_string();
        let pool = quil_rpc::ArchiveEndpointPool::new(Duration::ZERO);
        pool.add(address).await;
        let key = quil_p2p::generate_falcon_signing_key();
        let proof = storage_proof_bundle(1, &[(7, 1335, false, true)], 64);
        let (_, delivery) = submit_to_archives(&pool, Some(key.clone()), proof).await;
        assert_eq!((delivery.accepted, delivery.retry), (0, 1), "{delivery:?}");
        let [refusal] = &delivery.refusals[..] else {
            panic!("one refusal per archive: {delivery:?}");
        };
        assert!(refusal.contains("connect failed after "), "{refusal}");
        assert!(refusal.contains(" ms: "), "{refusal}");
        assert!(
            refusal.to_lowercase().contains("refused"),
            "the cause beneath the transport error is named: {refusal}"
        );
        let header = crate::master_node::reward_proofs::prover_bundle(
            quil_execution::global_intrinsic::frame_header::FrameHeader::default()
                .to_canonical_bytes()
                .unwrap(),
        )
        .unwrap();
        let (_, delivery) = submit_to_archives(&pool, Some(key), header).await;
        assert_eq!((delivery.accepted, delivery.retry), (0, 0), "{delivery:?}");
    }

    /// A storage epoch proof no archive took is sent again until one takes
    /// it, and holds no other queued message back meanwhile.
    #[tokio::test]
    async fn a_storage_proof_that_timed_out_is_sent_again_until_an_archive_takes_it() {
        let queue = Arc::new(SubmitRetryQueue::default());
        let proof = storage_proof_bundle(1, &[(7, 1335, false, true)], 64);
        queue.push(proof.clone());
        queue.push(b"other".to_vec());
        let sent = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let log = sent.clone();
        let proof_sends = Arc::new(AtomicUsize::new(0));
        let submit = {
            let (proof, proof_sends) = (proof.clone(), proof_sends.clone());
            move |bytes: Vec<u8>| {
                log.lock().unwrap().push(bytes.clone());
                let timed_out = bytes == proof && proof_sends.fetch_add(1, Ordering::SeqCst) < 2;
                async move {
                    if timed_out {
                        Delivery {
                            retry: 1,
                            refusals: vec![
                                "…aB3cD9: submit rejected: Cancelled: Timeout expired".into()
                            ],
                            ..Default::default()
                        }
                    } else {
                        Delivery {
                            accepted: 1,
                            ..Default::default()
                        }
                    }
                }
            }
        };
        tokio::time::timeout(
            Duration::from_secs(10),
            run_retries(queue.clone(), FAST, submit, || Some(0)),
        )
        .await
        .expect("the queue empties");
        assert_eq!(
            *sent.lock().unwrap(),
            vec![proof.clone(), b"other".to_vec(), proof.clone(), proof],
            "the proof is sent until taken, the other message in its first round"
        );
        assert_eq!(queue.len(), 0);
    }

    /// A storage epoch proof is sent again for as long as its window lasts,
    /// beyond the ten minutes other messages get, and given up as this
    /// node's GLOBAL frame reaches its window's end.
    #[tokio::test]
    async fn a_storage_proof_is_given_up_when_its_window_ends() {
        let queue = Arc::new(SubmitRetryQueue::default());
        let bundle = storage_proof_bundle(1, &[(7, 1335, false, true)], 64);
        let window_end = StorageProofSubmission::of(&bundle).unwrap().window_end;
        queue.push(bundle);
        let frame = Arc::new(std::sync::atomic::AtomicU64::new(window_end - 3));
        let sends = Arc::new(AtomicUsize::new(0));
        let submit = {
            let (frame, sends) = (frame.clone(), sends.clone());
            move |_bytes: Vec<u8>| {
                sends.fetch_add(1, Ordering::SeqCst);
                frame.fetch_add(1, Ordering::SeqCst);
                async {
                    Delivery {
                        retry: 1,
                        ..Default::default()
                    }
                }
            }
        };
        let no_time = RetryTiming {
            give_up: Duration::ZERO,
            proof_give_up: Duration::ZERO,
            ..FAST
        };
        let reader = frame.clone();
        tokio::time::timeout(
            Duration::from_secs(10),
            run_retries(queue.clone(), no_time, submit, move || {
                Some(reader.load(Ordering::SeqCst))
            }),
        )
        .await
        .expect("given up at the window's end");
        assert_eq!(
            sends.load(Ordering::SeqCst),
            3,
            "sent at each of the window's last three frames"
        );
        assert_eq!(queue.len(), 0);
    }

    /// A storage epoch proof's window ends where GLOBAL refuses it: a
    /// settlement's with its settlement window, a seal's as the epoch it
    /// seals begins (the same frame). Other bundles carry none.
    #[test]
    fn a_storage_proofs_window_ends_where_global_refuses_it() {
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        let settles = storage_proof_bundle(1, &[(7, 1335, false, true)], 8);
        let seals = storage_proof_bundle(1, &[(7, 1335, true, false)], 8);
        let end = settlement_window(1335).1;
        assert_eq!(
            StorageProofSubmission::of(&settles).unwrap().window_end,
            end
        );
        assert_eq!(
            StorageProofSubmission::of(&seals).unwrap().window_end,
            quil_types::consensus::epoch_start_frame(1337)
        );
        assert_eq!(end, quil_types::consensus::epoch_start_frame(1337));
        let both = storage_proof_bundle(1, &[(7, 1336, false, true), (8, 1335, true, true)], 8);
        assert_eq!(StorageProofSubmission::of(&both).unwrap().window_end, end);
        let header = crate::master_node::reward_proofs::prover_bundle(
            quil_execution::global_intrinsic::frame_header::FrameHeader::default()
                .to_canonical_bytes()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(StorageProofSubmission::of(&header), None);
        assert!(!super::carries_storage_proof(&header));
        assert!(super::carries_storage_proof(&settles));
    }

    /// An archive's peer listener whose collector is full: it refuses every
    /// submission for now. Returns its address and the submissions it saw.
    async fn full_archive() -> (String, Arc<AtomicUsize>) {
        let seen = Arc::new(AtomicUsize::new(0));
        let handler: quil_rpc::SubmitHandler = {
            let seen = seen.clone();
            Arc::new(move |_request| {
                seen.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    Err(quil_rpc::SubmitRefusal::retry_later(
                        "message collector rejected: rank buffer full",
                    ))
                })
            })
        };
        (archive_answering(handler).await, seen)
    }

    /// An archive's peer listener answering each submission with `handler`.
    /// Returns its address.
    async fn archive_answering(handler: quil_rpc::SubmitHandler) -> String {
        use quil_types::proto::global::global_service_server::GlobalServiceServer;
        use quil_types::proto::global::GlobalFrame;
        use tokio::net::TcpListener;
        struct NoFrames;
        impl quil_rpc::FrameLookup for NoFrames {
            fn get_latest_frame(&self) -> Result<GlobalFrame, String> {
                Err("no frames".into())
            }
            fn get_frame(&self, _frame_number: u64) -> Result<GlobalFrame, String> {
                Err("no frames".into())
            }
        }
        let server_key = quil_p2p::generate_falcon_signing_key();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let (streams_tx, streams) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (key, streams_tx) = (server_key.clone(), streams_tx.clone());
                tokio::spawn(async move {
                    if let Ok(stream) =
                        quil_rpc::pqnoise_channel::pq_server_handshake(tcp, &key).await
                    {
                        let _ = streams_tx.send(Ok::<_, std::io::Error>(stream));
                    }
                });
            }
        });
        let incoming = futures::stream::unfold(streams, |mut streams| async move {
            streams.recv().await.map(|stream| (stream, streams))
        });
        let service = GlobalServiceServer::new(
            quil_rpc::GlobalRpcServer::new(Arc::new(NoFrames)).with_submit_handler(handler),
        )
        .max_decoding_message_size(64 << 20);
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(incoming),
        );
        address
    }

    /// A worker's next part for a seat the retry queue holds, sent while
    /// every archive is full, takes the queued copy's place and goes at the
    /// queue's next round: the archives see one send of the seat, not that
    /// and another at once. Another seat's proof due no sooner is queued
    /// unsent while the archive rests; one due sooner goes at once.
    #[tokio::test]
    async fn a_seat_sent_again_while_queued_goes_at_the_queues_round() {
        use quil_engine::prover_message_transport::ProverMessageTransport;
        let (address, seen) = full_archive().await;
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(Duration::ZERO));
        pool.add(address).await;
        let transport = super::ProdProverMessageTransport {
            archive_pool: pool,
            clock_store: Arc::new(quil_store::testing::InMemoryClockStore::new()),
            p2p_handle: quil_p2p::node::P2PHandle::for_test(false),
            falcon_signing_key: Some(quil_p2p::generate_falcon_signing_key()),
            publish_to_blossomsub: false,
            retry_queue: Default::default(),
            join_header_check: Arc::new(|_: &quil_types::proto::global::GlobalFrame| true),
        };
        let first = transport
            .publish_prover_bundle(storage_proof_bundle(1, &[(7, 1335, false, true)], 64))
            .await;
        assert!(first.is_err(), "every archive refused it: {first:?}");
        assert_eq!(seen.load(Ordering::SeqCst), 1);
        assert_eq!(transport.retry_queue.len(), 1, "queued");
        let _ = transport
            .publish_prover_bundle(storage_proof_bundle(1, &[(7, 1335, false, true)], 65))
            .await;
        let sends = seen.load(Ordering::SeqCst);
        eprintln!("REACH seal-resend fold sends={sends}");
        assert_eq!(
            sends, 1,
            "seal-resend fold: the seat's next part went to the archives at once beside its queued copy"
        );
        assert_eq!(transport.retry_queue.len(), 1, "one copy queued");
        let _ = transport
            .publish_prover_bundle(storage_proof_bundle(1, &[(8, 1335, false, true)], 64))
            .await;
        let sends = seen.load(Ordering::SeqCst);
        eprintln!("REACH room-rest publish sends={sends}");
        assert_eq!(
            sends, 1,
            "room_rest: a proof due no sooner went to the archive resting after a refusal for room"
        );
        assert_eq!(transport.retry_queue.len(), 2, "queued unsent");
        let _ = transport
            .publish_prover_bundle(storage_proof_bundle(1, &[(9, 1334, false, true)], 64))
            .await;
        assert_eq!(
            seen.load(Ordering::SeqCst),
            2,
            "a proof due sooner goes at once"
        );
    }

    /// An archive refusing a proof for room rests: proofs whose window ends
    /// no sooner skip it until the rest ends, a proof due sooner does not,
    /// and the skipped send counts as a refusal for room, not a send.
    #[tokio::test]
    async fn an_archive_refusing_for_room_rests() {
        let rests = ArchiveRests::default();
        let calls = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let log = calls.clone();
        let submit = move |addr: String, _bytes: Vec<u8>| {
            log.lock().unwrap().push(addr.clone());
            async move {
                if addr.contains("full") {
                    Err((
                        addr,
                        "message collector rejected: rank buffer full".to_string(),
                        true,
                    ))
                } else {
                    Ok(addr)
                }
            }
        };
        let archives = vec!["full".to_string(), "taking".to_string()];
        let resting = |window_end| {
            Some(Resting {
                rests: &rests,
                window_end,
                rest: Duration::from_secs(60),
            })
        };
        let first = fan_out_resting(
            archives.clone(),
            vec![1],
            submit.clone(),
            true,
            resting(100),
        )
        .await;
        assert_eq!((first.accepted, first.room, first.rested), (1, 1, 0));
        let later = fan_out_resting(
            archives.clone(),
            vec![1],
            submit.clone(),
            true,
            resting(100),
        )
        .await;
        let full_sends = calls
            .lock()
            .unwrap()
            .iter()
            .filter(|addr| addr.contains("full"))
            .count();
        eprintln!("REACH room-rest fan-out full_sends={full_sends}");
        assert_eq!(
            full_sends, 1,
            "room_rest: the archive refusing for room was sent the next proof due no sooner"
        );
        assert_eq!(
            (later.accepted, later.retry, later.room, later.rested),
            (1, 1, 1, 1)
        );
        assert!(!later.unsent(), "the taking archive was sent to");
        assert!(
            later.refusals[0].contains("resting"),
            "{:?}",
            later.refusals
        );
        let sooner = fan_out_resting(archives, vec![1], submit, true, resting(99)).await;
        assert_eq!(
            sooner.rested, 0,
            "a proof due sooner goes to the resting archive"
        );
        assert_eq!(calls.lock().unwrap().len(), 5);
        // The rest ends at its time, and keeps the earliest refused window.
        let now = Instant::now();
        rests.refused_room("a", 200, now, Duration::from_secs(10));
        rests.refused_room("a", 150, now, Duration::from_secs(5));
        assert_eq!(rests.rests("a", 150, now), Some(Duration::from_secs(10)));
        assert_eq!(rests.rests("a", 149, now), None);
        assert_eq!(rests.rests("a", 200, now + Duration::from_secs(10)), None);
        assert_eq!(rests.rests("b", 200, now), None);
    }

    /// Queued proofs sent again while the only archive refuses each for
    /// room: rounds every few milliseconds, against an archive rest far
    /// longer, reach the archive once, not once a round.
    #[tokio::test]
    async fn queued_proofs_reach_a_full_archive_once_a_rest() {
        let queue = Arc::new(SubmitRetryQueue::default());
        for seat in 1..=3 {
            queue.push(storage_proof_bundle(1, &[(seat, 1335, false, true)], 64));
        }
        let sends = Arc::new(AtomicUsize::new(0));
        let rounds = Arc::new(AtomicUsize::new(0));
        let (counted, queue_in) = (sends.clone(), queue.clone());
        let rounds_in = rounds.clone();
        let task = tokio::spawn(run_retries(
            queue.clone(),
            FAST,
            move |bytes| {
                let (counted, queue_in) = (counted.clone(), queue_in.clone());
                rounds_in.fetch_add(1, Ordering::SeqCst);
                let window_end = StorageProofSubmission::of(&bytes).unwrap().window_end;
                async move {
                    let submit = move |addr: String, _bytes: Vec<u8>| {
                        counted.fetch_add(1, Ordering::SeqCst);
                        async move {
                            Err((
                                addr,
                                "message collector rejected: rank buffer full".to_string(),
                                true,
                            ))
                        }
                    };
                    let resting = Resting {
                        rests: &queue_in.rests,
                        window_end,
                        rest: FAST.room_rest,
                    };
                    fan_out_resting(vec!["full".into()], bytes, submit, true, Some(resting)).await
                }
            },
            || None,
        ));
        while rounds.load(Ordering::SeqCst) < 30 {
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        task.abort();
        let sends = sends.load(Ordering::SeqCst);
        eprintln!("REACH room-rest rounds sends={sends}");
        assert_eq!(
            sends, 1,
            "room_rest: queued proofs went to the resting archive at each round"
        );
        assert_eq!(queue.len(), 3, "all still queued");
    }

    /// An archive refusing a proof for room rests at least two GLOBAL
    /// frames at mainnet's pace (`RETRY_TIMING.room_rest`, 40 s), and
    /// jitter adds up to half: never less.
    #[tokio::test]
    async fn a_room_rest_lasts_at_least_two_frames() {
        let rests = ArchiveRests::default();
        let submit = |addr: String, _bytes: Vec<u8>| async move {
            Err((
                addr,
                "message collector rejected: rank buffer full".to_string(),
                true,
            ))
        };
        let archives: Vec<String> = (0..8).map(|n| format!("full-{n}")).collect();
        let resting = Resting {
            rests: &rests,
            window_end: 100,
            rest: RETRY_TIMING.room_rest,
        };
        let before = Instant::now();
        let delivery =
            fan_out_resting(archives.clone(), vec![1], submit, true, Some(resting)).await;
        let sent = before.elapsed();
        assert_eq!(delivery.room, 8, "each archive refused for room");
        let lefts: Vec<Duration> = archives
            .iter()
            .map(|addr| rests.rests(addr, 100, before).expect("each archive rests"))
            .collect();
        eprintln!("REACH room rest lengths={lefts:?}");
        let (least, most) = (Duration::from_secs(40), Duration::from_secs(60) + sent);
        assert!(
            lefts.iter().all(|left| *left >= least),
            "room_jitter: a rest shorter than two GLOBAL frames: {lefts:?}"
        );
        assert!(
            lefts.iter().all(|left| *left <= most),
            "a rest longer than 60 s: {lefts:?}"
        );
    }

    /// A queued proof refused for room by the only archive goes to it
    /// again once the archive's rest ends, and is delivered then, not
    /// before.
    #[tokio::test]
    async fn a_queued_proof_goes_again_once_its_rest_ends() {
        let timing = RetryTiming {
            room_rest: Duration::from_millis(50),
            ..FAST
        };
        let queue = Arc::new(SubmitRetryQueue::default());
        queue.push(storage_proof_bundle(1, &[(1, 1335, false, true)], 64));
        let sends = Arc::new(std::sync::Mutex::new(Vec::<Instant>::new()));
        let rounds = Arc::new(std::sync::Mutex::new(Vec::<Instant>::new()));
        let (sends_in, rounds_in, queue_in) = (sends.clone(), rounds.clone(), queue.clone());
        let task = tokio::spawn(run_retries(
            queue.clone(),
            timing,
            move |bytes| {
                let (sends_in, queue_in) = (sends_in.clone(), queue_in.clone());
                rounds_in.lock().unwrap().push(Instant::now());
                let window_end = StorageProofSubmission::of(&bytes).unwrap().window_end;
                async move {
                    let submit = move |addr: String, _bytes: Vec<u8>| {
                        let first = {
                            let mut sends = sends_in.lock().unwrap();
                            sends.push(Instant::now());
                            sends.len() == 1
                        };
                        async move {
                            if first {
                                Err((
                                    addr,
                                    "message collector rejected: rank buffer full".to_string(),
                                    true,
                                ))
                            } else {
                                Ok(addr)
                            }
                        }
                    };
                    let resting = Resting {
                        rests: &queue_in.rests,
                        window_end,
                        rest: timing.room_rest,
                    };
                    fan_out_resting(vec!["full".into()], bytes, submit, true, Some(resting)).await
                }
            },
            || None,
        ));
        // Progress: the proof delivered, or 20 rounds after the longest
        // rest (with jitter) ended.
        let longest = timing.room_rest + timing.room_rest / 2;
        let rounds_past_rest = || {
            let first = sends.lock().unwrap().first().copied();
            first.map_or(0, |first| {
                let rounds = rounds.lock().unwrap();
                rounds.iter().filter(|at| **at > first + longest).count()
            })
        };
        let guard = Instant::now();
        while queue.len() > 0
            && rounds_past_rest() < 20
            && guard.elapsed() < Duration::from_secs(30)
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        task.abort();
        let sends = sends.lock().unwrap().clone();
        let rounds = rounds.lock().unwrap().len();
        eprintln!("REACH rest end sends={} rounds={rounds}", sends.len());
        assert_eq!(
            sends.len(),
            2,
            "rest_ends: the queued proof did not go again once its rest ended ({rounds} rounds)"
        );
        assert!(
            sends[1] - sends[0] >= timing.room_rest,
            "sent again before its rest ended"
        );
        assert_eq!(queue.len(), 0, "delivered once sent again");
    }

    /// A proof handed over once its window ended is not sent: GLOBAL
    /// refuses it whole. Its window counts it undelivered.
    #[tokio::test]
    async fn a_proof_whose_window_ended_is_not_sent() {
        use quil_engine::prover_message_transport::ProverMessageTransport;
        use quil_types::store::ClockStore;
        let (address, seen) = full_archive().await;
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(Duration::ZERO));
        pool.add(address).await;
        let late = storage_proof_bundle(1, &[(7, 1335, false, true)], 64);
        let window_end = StorageProofSubmission::of(&late).unwrap().window_end;
        let clock_store = quil_store::testing::InMemoryClockStore::new();
        let frame = quil_types::proto::global::GlobalFrame {
            header: Some(quil_types::proto::global::GlobalFrameHeader {
                frame_number: window_end,
                ..Default::default()
            }),
            ..Default::default()
        };
        let txn = clock_store.new_transaction(false).unwrap();
        clock_store
            .put_global_clock_frame(&frame, txn.as_ref())
            .unwrap();
        let transport = super::ProdProverMessageTransport {
            archive_pool: pool,
            clock_store: Arc::new(clock_store),
            p2p_handle: quil_p2p::node::P2PHandle::for_test(false),
            falcon_signing_key: Some(quil_p2p::generate_falcon_signing_key()),
            publish_to_blossomsub: false,
            retry_queue: Default::default(),
            join_header_check: Arc::new(|_: &quil_types::proto::global::GlobalFrame| true),
        };
        let _ = transport.publish_prover_bundle(late).await;
        let sends = seen.load(Ordering::SeqCst);
        eprintln!("REACH late-proof publish sends={sends}");
        assert_eq!(
            sends, 0,
            "late_skip: a proof whose window ended went to the archives"
        );
        assert_eq!(transport.retry_queue.len(), 0, "nor queued");
        assert_eq!(transport.retry_queue.undelivered_in(window_end), 1);
        let due = storage_proof_bundle(1, &[(7, 1336, false, true)], 64);
        let _ = transport.publish_prover_bundle(due).await;
        assert_eq!(seen.load(Ordering::SeqCst), 1, "a proof still due went");
    }

    /// A round sends the storage epoch proof whose window ends soonest first,
    /// whichever was queued first.
    #[tokio::test]
    async fn queued_proofs_are_sent_again_soonest_window_first() {
        let queue = Arc::new(SubmitRetryQueue::default());
        let later = storage_proof_bundle(1, &[(7, 1336, false, true)], 64);
        let sooner = storage_proof_bundle(2, &[(7, 1335, false, true)], 64);
        queue.push(later.clone());
        queue.push(sooner.clone());
        let sent = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let log = sent.clone();
        run_retries(
            queue.clone(),
            FAST,
            move |bytes| {
                log.lock().unwrap().push(bytes);
                async {
                    Delivery {
                        accepted: 1,
                        ..Default::default()
                    }
                }
            },
            || None,
        )
        .await;
        let sent = sent.lock().unwrap().clone();
        let first = sent.first().map(|bytes| bytes == &sooner);
        eprintln!(
            "REACH seal-resend order sends={} sooner_first={first:?}",
            sent.len()
        );
        assert_eq!(
            sent,
            vec![sooner, later],
            "seal-resend order: the proof due sooner was not sent first"
        );
    }

    /// Once a window ends, one line tells what became of its storage epoch
    /// proofs; a proof undelivered makes it a warning.
    #[tokio::test]
    async fn a_windows_storage_epoch_proofs_are_summarized_once_it_ends() {
        #[derive(Clone)]
        struct Lines(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Lines {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(bytes)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured: Arc<std::sync::Mutex<Vec<u8>>> = Default::default();
        let writer = Lines(captured.clone());
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish(),
        );
        let queue = Arc::new(SubmitRetryQueue::default());
        let bundle = storage_proof_bundle(1, &[(7, 1335, false, true)], 64);
        let window_end = StorageProofSubmission::of(&bundle).unwrap().window_end;
        queue.push(bundle);
        let frame = Arc::new(std::sync::atomic::AtomicU64::new(window_end - 1));
        let submit = {
            let frame = frame.clone();
            move |_bytes: Vec<u8>| {
                frame.fetch_add(1, Ordering::SeqCst);
                async {
                    Delivery {
                        retry: 1,
                        ..Default::default()
                    }
                }
            }
        };
        let reader = frame.clone();
        tokio::time::timeout(
            Duration::from_secs(10),
            run_retries(queue.clone(), FAST, submit, move || {
                Some(reader.load(Ordering::SeqCst))
            }),
        )
        .await
        .expect("given up at the window's end");
        let text = String::from_utf8_lossy(&captured.lock().unwrap()).into_owned();
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("storage epoch proofs of a window that ended"))
            .collect();
        eprintln!("REACH seal-resend summary lines={}", lines.len());
        assert_eq!(
            lines.len(),
            1,
            "seal-resend summary: {} window lines in {text}",
            lines.len()
        );
        assert!(
            lines[0].contains("WARN")
                && lines[0].contains("epoch=1335")
                && lines[0].contains("sent=1")
                && lines[0].contains("refused=1")
                && lines[0].contains("undelivered=1"),
            "seal-resend summary-fields: {}",
            lines[0]
        );
    }

    /// This thread's log lines, as the formatter writes them, while it
    /// lives.
    struct Logs {
        text: Arc<std::sync::Mutex<Vec<u8>>>,
        _guard: tracing::subscriber::DefaultGuard,
    }

    impl Logs {
        fn capture() -> Self {
            #[derive(Clone)]
            struct Lines(Arc<std::sync::Mutex<Vec<u8>>>);
            impl std::io::Write for Lines {
                fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                    self.0.lock().unwrap().write(bytes)
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let text: Arc<std::sync::Mutex<Vec<u8>>> = Default::default();
            let writer = Lines(text.clone());
            let _guard = tracing::subscriber::set_default(
                tracing_subscriber::fmt()
                    .with_ansi(false)
                    .with_writer(move || writer.clone())
                    .finish(),
            );
            Self { text, _guard }
        }

        /// The lines so far that contain `text`.
        fn lines(&self, text: &str) -> Vec<String> {
            String::from_utf8_lossy(&self.text.lock().unwrap())
                .lines()
                .filter(|line| line.contains(text))
                .map(str::to_owned)
                .collect()
        }
    }

    /// Storage epoch proofs that overfill the retry queue by `extra`, each
    /// of its own seat.
    fn overfull_queue(extra: usize) -> Vec<Vec<u8>> {
        (0..super::RETRY_MAX_MESSAGES + extra)
            .map(|i| storage_proof_bundle(1 + (i / 256) as u8, &[(i as u8, 1335, false, true)], 8))
            .collect()
    }

    /// Storage epoch proofs a full retry queue drops count as dropped, not
    /// undelivered (a worker's later send of their seats may still deliver
    /// them), in their window's summary, which warns; the drops of one
    /// interval make one warning, not one each. Until 2026-11-15 the summary
    /// missed them and every drop logged its own unstructured line.
    #[test]
    fn a_full_retry_queue_counts_its_dropped_proofs_and_warns_once() {
        let logs = Logs::capture();
        let queue = SubmitRetryQueue::default();
        let bundles = overfull_queue(3);
        let window_end = StorageProofSubmission::of(&bundles[0]).unwrap().window_end;
        for bundle in bundles {
            queue.push(bundle);
        }
        assert_eq!(queue.len(), super::RETRY_MAX_MESSAGES, "the queue is full");
        queue.report_windows(Some(window_end));
        let windows = logs.lines("storage epoch proofs of a window that ended");
        let drops = logs.lines("retry queue full");
        eprintln!(
            "REACH retry-drop windows={} drop_lines={}",
            windows.len(),
            drops.len()
        );
        assert!(
            windows.len() == 1
                && windows[0].contains("WARN")
                && windows[0].contains(" undelivered=0 dropped=3"),
            "retry-drop tally: the window's summary did not warn of 3 dropped proofs, none undelivered: {windows:?}"
        );
        assert!(
            drops.len() == 1 && drops[0].contains(" dropped=1 proofs=1 "),
            "retry-drop warn-once: not one line for the first of 3 drops within one interval: {drops:?}"
        );
    }

    /// Drops still unlogged when the retry queue drains are logged then,
    /// not with the next full queue, maybe hours later and with the wrong
    /// interval and queue size. Until 2026-11-15 they waited for it.
    #[tokio::test]
    async fn drops_left_unlogged_are_logged_once_the_retry_queue_drains() {
        let logs = Logs::capture();
        let queue = Arc::new(SubmitRetryQueue::default());
        for bundle in overfull_queue(3) {
            queue.push(bundle);
        }
        let submit = |_bytes: Vec<u8>| async {
            Delivery {
                accepted: 1,
                ..Default::default()
            }
        };
        tokio::time::timeout(
            Duration::from_secs(10),
            run_retries(queue.clone(), FAST, submit, || Some(0)),
        )
        .await
        .expect("the queue empties");
        assert_eq!(queue.len(), 0);
        let drops = logs.lines("retry queue full");
        eprintln!("REACH retry-drop-flush drop_lines={}", drops.len());
        assert!(
            drops.len() == 2
                && drops[0].contains(" dropped=1 proofs=1 ")
                && drops[1].contains(" dropped=2 proofs=2 ")
                && drops[1].contains(" queued=0 "),
            "retry-drop flush: the 2 drops left unlogged were not logged as the queue drained: {drops:?}"
        );
    }

    /// Drops after a line wait out its interval, then make one line at the
    /// next retry round, and no more while none are new.
    #[test]
    fn drops_left_unlogged_are_logged_once_their_interval_is_over() {
        let logs = Logs::capture();
        let queue = SubmitRetryQueue::default();
        for bundle in overfull_queue(3) {
            queue.push(bundle);
        }
        queue.report_drops(false);
        assert_eq!(
            logs.lines("retry queue full").len(),
            1,
            "retry-drop interval: a line for the drops within the interval"
        );
        {
            let mut drops = queue.drops.lock().unwrap();
            let interval = super::RETRY_DROP_LOG_EVERY;
            drops.logged = drops.logged.and_then(|at| at.checked_sub(interval));
        }
        queue.report_drops(false);
        queue.report_drops(false);
        let drops = logs.lines("retry queue full");
        eprintln!("REACH retry-drop-interval drop_lines={}", drops.len());
        assert!(
            drops.len() == 2
                && drops[1].contains(" dropped=2 proofs=2 ")
                && !drops[1].contains("since_secs=unknown"),
            "retry-drop interval: the 2 drops left unlogged were not logged once at the interval's end: {drops:?}"
        );
    }

    /// A later proof of the same seats replaces the queued one, and a
    /// delivered proof drops the queued proofs it covers, but no proof of
    /// another seat, epoch, part or member.
    #[test]
    fn a_proof_of_the_same_seats_replaces_or_settles_a_queued_one() {
        let queue = SubmitRetryQueue::default();
        queue.push(storage_proof_bundle(1, &[(7, 1335, false, true)], 8));
        queue.push(storage_proof_bundle(1, &[(7, 1335, false, true)], 9));
        assert_eq!(queue.len(), 1, "the later proof replaced the earlier");
        queue.push(storage_proof_bundle(1, &[(8, 1335, false, true)], 8));
        queue.push(storage_proof_bundle(1, &[(7, 1334, false, true)], 8));
        queue.push(storage_proof_bundle(1, &[(7, 1335, true, false)], 8));
        queue.push(storage_proof_bundle(2, &[(7, 1335, false, true)], 8));
        assert_eq!(queue.len(), 5);
        let delivered = StorageProofSubmission::of(&storage_proof_bundle(
            1,
            &[(7, 1335, false, true), (8, 1335, false, true)],
            8,
        ))
        .unwrap();
        assert_eq!(queue.delivered(&delivered), 2);
        assert_eq!(queue.len(), 3);
        let sealing_too =
            StorageProofSubmission::of(&storage_proof_bundle(1, &[(7, 1335, true, true)], 8))
                .unwrap();
        assert_eq!(queue.delivered(&sealing_too), 1, "the seal of 1335");
        assert_eq!(queue.len(), 2);
    }

    /// GLOBAL applies only the first of two proofs settling one seat's
    /// epoch: a later proof settling a queued proof's seat takes its place,
    /// and a delivered one drops it, though the queued one also seals that
    /// seat or settles another; a proof only sealing that seat, or settling
    /// it for another epoch or member, stays.
    #[test]
    fn a_later_proof_settling_a_queued_seat_replaces_the_queued_one() {
        let queue = SubmitRetryQueue::default();
        let seats = |queue: &SubmitRetryQueue| -> Vec<Vec<(u8, u64, bool, bool)>> {
            queue
                .pending
                .lock()
                .unwrap()
                .iter()
                .map(|queued| {
                    let proof = queued.proof.as_ref().unwrap();
                    proof
                        .seats
                        .iter()
                        .map(|(shard, epoch, seals, settles)| (shard[0], *epoch, *seals, *settles))
                        .collect()
                })
                .collect()
        };
        // Sealing and settling seat 7, as a first attempt does.
        queue.push(storage_proof_bundle(1, &[(7, 1335, true, true)], 8));
        // Settling seats 8 and 9 together.
        queue.push(storage_proof_bundle(
            1,
            &[(8, 1335, false, true), (9, 1335, false, true)],
            8,
        ));
        // Only sealing seat 7; another member; another epoch.
        queue.push(storage_proof_bundle(1, &[(7, 1335, true, false)], 9));
        queue.push(storage_proof_bundle(2, &[(7, 1335, false, true)], 8));
        queue.push(storage_proof_bundle(
            1,
            &[(7, 1334, false, true), (6, 1334, false, true)],
            8,
        ));
        assert_eq!(queue.len(), 5);
        let later = [(7, 1335, false, true), (8, 1335, false, true)];
        queue.push(storage_proof_bundle(1, &later, 8));
        eprintln!("REACH settled-seat queue holds {}", queue.len());
        assert_eq!(
            seats(&queue),
            vec![
                vec![(7, 1335, true, false)],
                vec![(7, 1335, false, true)],
                vec![(7, 1334, false, true), (6, 1334, false, true)],
                later.to_vec(),
            ],
            "the later proof replaced the two settling seat 7 or 8 of 1335"
        );
        let delivered =
            StorageProofSubmission::of(&storage_proof_bundle(1, &[(7, 1334, false, true)], 8))
                .unwrap();
        assert_eq!(queue.delivered(&delivered), 1, "the settlement of 1334");
        assert_eq!(queue.len(), 3);
    }

    /// This node's view of member 1's seat slots, shared with the queue's.
    type SettledSet = Arc<std::sync::Mutex<Slots>>;

    /// Seat slots (shard byte, epoch) of member 1 this node's view shows
    /// closed, and those whose registration it shows sealed.
    #[derive(Default)]
    struct Slots {
        closed: std::collections::HashSet<(u8, u64)>,
        sealed: std::collections::HashSet<(u8, u64)>,
    }

    /// A [`SettledSet`], shared with the queue's view of seat slots.
    fn settled_view() -> (SettledSet, super::SettledSeat) {
        let settled: SettledSet = Default::default();
        let view = settled.clone();
        let seat: super::SettledSeat =
            Arc::new(move |member: &[u8; 32], shard: &[u8], epoch: u64| {
                let slots = view.lock().unwrap();
                let at = (shard[0], epoch);
                super::SlotState {
                    closed: *member == [1; 32] && slots.closed.contains(&at),
                    sealed: *member == [1; 32] && slots.sealed.contains(&at),
                }
            });
        (settled, seat)
    }

    /// GLOBAL refuses a proof whole when one of its seats settles an epoch
    /// already settled: a queued proof holding a seat this node's view
    /// shows settled is not sent again, and the proof of its other seats
    /// queued beside it is.
    #[tokio::test]
    async fn a_queued_proof_holding_a_settled_seat_is_not_sent_again() {
        let (settled, view) = settled_view();
        let queue = Arc::new(SubmitRetryQueue::reading_slots(view));
        let group = storage_proof_bundle(1, &[(7, 1495, false, true), (9, 1495, false, true)], 8);
        let alone = storage_proof_bundle(1, &[(8, 1495, false, true)], 8);
        queue.push(group.clone());
        queue.push(alone.clone());
        assert_eq!(queue.len(), 2, "both proofs queued");
        // Seat 9 settled by another proof while the group waited.
        settled.lock().unwrap().closed.insert((9, 1495));
        let sent = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let log = sent.clone();
        run_retries(
            queue.clone(),
            FAST,
            move |bytes| {
                log.lock().unwrap().push(bytes);
                async {
                    Delivery {
                        accepted: 1,
                        ..Default::default()
                    }
                }
            },
            || Some(1),
        )
        .await;
        let sent = sent.lock().unwrap().clone();
        eprintln!("REACH settled-seat resend sends={}", sent.len());
        assert!(
            !sent.contains(&group),
            "settled_resend: the proof holding settled seat 9 was sent again"
        );
        assert_eq!(sent, vec![alone], "the proof of seat 8 was sent");
        assert_eq!(queue.len(), 0);
    }

    /// GLOBAL closes a slot no proof settled once its frame reaches the
    /// settlement window's end, the frame a queued proof's window ends at:
    /// that proof is given up as undelivered, its window's line a warning,
    /// never dropped as one holding a settled seat.
    #[tokio::test]
    async fn a_queued_proof_whose_window_ended_is_undelivered_not_settled() {
        #[derive(Clone)]
        struct Lines(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Lines {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(bytes)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let captured: Arc<std::sync::Mutex<Vec<u8>>> = Default::default();
        let writer = Lines(captured.clone());
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer.clone())
                .finish(),
        );
        let (settled, view) = settled_view();
        let queue = Arc::new(SubmitRetryQueue::reading_slots(view));
        let bundle = storage_proof_bundle(1, &[(17, 1495, false, true)], 8);
        let window_end = StorageProofSubmission::of(&bundle).unwrap().window_end;
        queue.push(bundle);
        assert_eq!(queue.len(), 1, "the proof of seat 17 queued");
        // GLOBAL's frame reached the window's end: the slot shows closed.
        settled.lock().unwrap().closed.insert((17, 1495));
        let sends = Arc::new(AtomicUsize::new(0));
        let count = sends.clone();
        tokio::time::timeout(
            Duration::from_secs(10),
            run_retries(
                queue.clone(),
                FAST,
                move |_bytes: Vec<u8>| {
                    count.fetch_add(1, Ordering::SeqCst);
                    async {
                        Delivery {
                            accepted: 1,
                            ..Default::default()
                        }
                    }
                },
                move || Some(window_end),
            ),
        )
        .await
        .expect("given up at the window's end");
        let text = String::from_utf8_lossy(&captured.lock().unwrap()).into_owned();
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("storage epoch proofs of a window that ended"))
            .collect();
        eprintln!("REACH settled-seat expired window lines={}", lines.len());
        assert_eq!(lines.len(), 1, "one window line in {text}");
        assert!(
            lines[0].contains("WARN")
                && lines[0].contains("undelivered=1")
                && !lines[0].contains("settled=1"),
            "expired_settled: the proof of seat 17, its window ended, was not counted undelivered: {}",
            lines[0]
        );
        assert!(
            text.contains("storage epoch proof undelivered when its window ended"),
            "the proof's own undelivered line: {text}"
        );
        assert_eq!(sends.load(Ordering::SeqCst), 0, "not sent after its window");
        assert_eq!(queue.len(), 0);
    }

    /// An archive taking a proof that holds a seat already settled drops no
    /// queued proof: GLOBAL refuses it whole, so it seals and settles none
    /// of the seats it shares with them.
    #[test]
    fn an_accepted_proof_holding_a_settled_seat_drops_no_queued_proof() {
        let (settled, view) = settled_view();
        let queue = SubmitRetryQueue::reading_slots(view);
        settled.lock().unwrap().closed.insert((9, 1495));
        let alone = storage_proof_bundle(1, &[(8, 1495, false, true)], 8);
        queue.push(alone.clone());
        let taken = StorageProofSubmission::of(&storage_proof_bundle(
            1,
            &[(8, 1495, false, true), (9, 1495, false, true)],
            8,
        ))
        .unwrap();
        let superseded = queue.delivered(&taken);
        eprintln!("REACH settled-seat acceptance superseded={superseded}");
        assert_eq!(
            superseded, 0,
            "settled_supersedes: a proof holding settled seat 9 dropped the queued proof of seat 8"
        );
        assert_eq!(queue.len(), 1);
    }

    /// A proof sent again from the retry queue, taken by an archive as
    /// another proof settled one of its seats, drops no queued proof: GLOBAL
    /// refuses it whole, so the seal queued beside it still goes.
    #[tokio::test]
    async fn a_resent_proof_taken_as_its_seat_settled_drops_no_queued_proof() {
        let (settled, view) = settled_view();
        let queue = Arc::new(SubmitRetryQueue::reading_slots(view));
        let group = storage_proof_bundle(1, &[(10, 1495, true, true), (11, 1495, false, true)], 8);
        let seal = storage_proof_bundle(1, &[(10, 1495, true, false)], 8);
        queue.push(group.clone());
        queue.push(seal.clone());
        assert_eq!(queue.len(), 2, "the seal queued beside the group");
        let sent = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let log = sent.clone();
        let race = (group.clone(), settled.clone());
        run_retries(
            queue.clone(),
            FAST,
            move |bytes| {
                if bytes == race.0 {
                    race.1.lock().unwrap().closed.insert((11, 1495));
                }
                log.lock().unwrap().push(bytes);
                async {
                    Delivery {
                        accepted: 1,
                        ..Default::default()
                    }
                }
            },
            || Some(1),
        )
        .await;
        let sent = sent.lock().unwrap().clone();
        eprintln!("REACH settled-seat resent acceptance sends={}", sent.len());
        assert_eq!(
            sent,
            vec![group, seal],
            "settled_resent_supersedes: the seal of seat 10 was dropped by a resent proof holding settled seat 11"
        );
    }

    /// A proof holding a seat this node's view shows settled is not sent:
    /// GLOBAL refuses it whole, and it would take the archives' room.
    #[tokio::test]
    async fn a_proof_holding_a_settled_seat_is_not_sent() {
        use quil_engine::prover_message_transport::ProverMessageTransport;
        let (settled, view) = settled_view();
        settled.lock().unwrap().closed.insert((9, 1495));
        assert!(
            view(&[1; 32], &[9; 35], 1495).closed,
            "seat 9 shows settled"
        );
        let (address, seen) = full_archive().await;
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(Duration::ZERO));
        pool.add(address).await;
        let transport = super::ProdProverMessageTransport {
            archive_pool: pool,
            clock_store: Arc::new(quil_store::testing::InMemoryClockStore::new()),
            p2p_handle: quil_p2p::node::P2PHandle::for_test(false),
            falcon_signing_key: Some(quil_p2p::generate_falcon_signing_key()),
            publish_to_blossomsub: false,
            retry_queue: Arc::new(SubmitRetryQueue::reading_slots(view)),
            join_header_check: Arc::new(|_: &quil_types::proto::global::GlobalFrame| true),
        };
        let group = storage_proof_bundle(1, &[(8, 1495, false, true), (9, 1495, false, true)], 64);
        let window_end = StorageProofSubmission::of(&group).unwrap().window_end;
        let _ = transport.publish_prover_bundle(group).await;
        let sends = seen.load(Ordering::SeqCst);
        eprintln!("REACH settled-seat publish sends={sends}");
        assert_eq!(
            sends, 0,
            "settled_publish: the proof holding settled seat 9 went to the archives"
        );
        assert_eq!(transport.retry_queue.len(), 0, "nor queued");
        assert_eq!(
            transport.retry_queue.settled_in(window_end),
            1,
            "settled_tally: a proof held back for a settled seat was not counted in its window"
        );
        let _ = transport
            .publish_prover_bundle(storage_proof_bundle(1, &[(8, 1495, false, true)], 64))
            .await;
        assert_eq!(seen.load(Ordering::SeqCst), 1, "the proof of seat 8 went");
    }

    /// GLOBAL refuses a proof whole when one of its seats seals a
    /// registration already sealed: a queued proof sealing a registration
    /// this node's view shows sealed is not sent again, and the seal queued
    /// beside it is. Its window's line counts it.
    #[tokio::test]
    async fn a_queued_proof_sealing_a_sealed_registration_is_not_sent_again() {
        let (settled, view) = settled_view();
        let queue = Arc::new(SubmitRetryQueue::reading_slots(view));
        // Seals of seats 10 and 12 together, and of seat 13 alone.
        let group = storage_proof_bundle(1, &[(10, 1495, true, false), (12, 1495, true, false)], 8);
        let alone = storage_proof_bundle(1, &[(13, 1495, true, false)], 8);
        let window_end = StorageProofSubmission::of(&group).unwrap().window_end;
        queue.push(group.clone());
        queue.push(alone.clone());
        assert_eq!(queue.len(), 2, "both proofs queued");
        // Seat 12's registration for epoch 1497 sealed by another proof
        // while the group waited; its slot is open.
        settled.lock().unwrap().sealed.insert((12, 1497));
        let sent = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let log = sent.clone();
        run_retries(
            queue.clone(),
            FAST,
            move |bytes| {
                log.lock().unwrap().push(bytes);
                async {
                    Delivery {
                        accepted: 1,
                        ..Default::default()
                    }
                }
            },
            || Some(1),
        )
        .await;
        let sent = sent.lock().unwrap().clone();
        eprintln!("REACH settled-seat sealed sends={}", sent.len());
        assert!(
            !sent.contains(&group),
            "sealed_resend: the proof sealing seat 12's sealed registration was sent again"
        );
        assert_eq!(sent, vec![alone], "the seal of seat 13 was sent");
        assert_eq!(queue.len(), 0);
        assert_eq!(
            queue.settled_in(window_end),
            1,
            "settled_tally: a proof held back for a settled seat was not counted in its window"
        );
    }

    /// Each check reads only the part a seat carries: a seal goes though
    /// its seat's slot shows settled, and a settlement though the
    /// registration two epochs on shows sealed; a settlement of a slot
    /// shown settled does not go.
    #[tokio::test]
    async fn a_seal_of_a_settled_slot_and_a_settlement_under_a_sealed_registration_are_sent() {
        let (settled, view) = settled_view();
        let queue = Arc::new(SubmitRetryQueue::reading_slots(view.clone()));
        // Seat 14 seals its registration for 1497, seat 15 settles 1495,
        // seat 16 settles 1495.
        let seal = storage_proof_bundle(1, &[(14, 1495, true, false)], 8);
        let settle = storage_proof_bundle(1, &[(15, 1495, false, true)], 8);
        let again = storage_proof_bundle(1, &[(16, 1495, false, true)], 8);
        for bundle in [&seal, &settle, &again] {
            queue.push(bundle.clone());
        }
        assert_eq!(queue.len(), 3, "the three proofs queued");
        // Seat 14's slot of 1495 settled, seat 15's registration for 1497
        // sealed and seat 16's slot of 1495 settled, by other proofs.
        {
            let mut slots = settled.lock().unwrap();
            slots.closed.extend([(14, 1495), (16, 1495)]);
            slots.sealed.insert((15, 1497));
        }
        let shown = |shard: u8, epoch| view(&[1; 32], &[shard; 35], epoch);
        assert!(
            shown(14, 1495).closed && !shown(14, 1497).sealed,
            "seat 14's slot shows settled, its registration unsealed"
        );
        assert!(
            !shown(15, 1495).closed && shown(15, 1497).sealed,
            "seat 15's slot shows open, its registration sealed"
        );
        assert!(shown(16, 1495).closed, "seat 16's slot shows settled");
        let sent = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let log = sent.clone();
        run_retries(
            queue.clone(),
            FAST,
            move |bytes| {
                log.lock().unwrap().push(bytes);
                async {
                    Delivery {
                        accepted: 1,
                        ..Default::default()
                    }
                }
            },
            || Some(1),
        )
        .await;
        let sent = sent.lock().unwrap().clone();
        eprintln!("REACH settled-seat parts sends={}", sent.len());
        assert!(
            !sent.contains(&again),
            "settled_parts: the proof settling seat 16's settled slot was sent again"
        );
        assert!(
            sent.contains(&seal),
            "settles_part: the seal of seat 14 was held back as its slot settled"
        );
        assert!(
            sent.contains(&settle),
            "seals_part: the settlement of seat 15 was held back as its registration sealed"
        );
        assert_eq!(queue.len(), 0);
    }

    /// The production view of seat slots reads the slots the registry holds:
    /// an open slot shows open, a settled or expired one closed, a sealed
    /// registration sealed; a slot it lacks shows open and unsealed.
    #[test]
    fn the_registry_view_shows_open_settled_expired_and_sealed_slots() {
        use quil_execution::global_intrinsic::storage_seat::{Outcome, SeatSlot};
        let registry = Arc::new(quil_execution::prover_registry::SharedProverRegistry::new());
        let slots = [
            (1495, Outcome::Open, Some(100)),
            (1496, Outcome::Settled(200), Some(150)),
            (1497, Outcome::Expired(300), None),
            (1498, Outcome::Open, None),
        ];
        registry.write_for_tests(|cache| {
            for (epoch, outcome, sealed_at) in slots {
                let slot = SeatSlot {
                    epoch,
                    leaves: vec![vec![0]],
                    registered_at: 50,
                    sealed_at,
                    outcome,
                    ..Default::default()
                };
                cache.insert_storage_seat_slot_for_tests(&[1; 32], &[7; 35], slot.view());
            }
        });
        let view = super::registry_slots(registry);
        let shown: Vec<(u64, super::SlotState)> = (1495..=1499)
            .map(|epoch| (epoch, view(&[1; 32], &[7; 35], epoch)))
            .collect();
        eprintln!("REACH settled-seat view {shown:?}");
        let state = |closed, sealed| super::SlotState { closed, sealed };
        assert_eq!(
            shown,
            vec![
                (1495, state(false, true)),
                (1496, state(true, true)),
                (1497, state(true, false)),
                (1498, state(false, false)),
                (1499, state(false, false)),
            ],
            "slot_view: the registry view misread open, settled, expired or sealed slots"
        );
        assert_eq!(
            view(&[2; 32], &[7; 35], 1496),
            super::SlotState::default(),
            "another member's seat shows open"
        );
    }

    /// A queued proof dropped for one seat this node's view shows sealed
    /// names the seats it leaves owed and its window's end: the other seat
    /// of such a proof was sent again a frame after its window, and no line
    /// named it (devnet, 2026-11-22).
    #[test]
    fn a_proof_dropped_for_a_sealed_seat_names_the_seats_it_leaves_owed() {
        let (settled, view) = settled_view();
        let queue = SubmitRetryQueue::reading_slots(view);
        let group = storage_proof_bundle(1, &[(7, 1495, true, false), (9, 1495, true, false)], 8);
        let window_end = super::StorageProofSubmission::of(&group)
            .expect("premise: a storage epoch proof")
            .window_end;
        queue.push(group);
        settled.lock().unwrap().sealed.insert((9, 1497));
        let logs = Logs::capture();
        queue.drop_settled(FAST, &|| Some(5));
        assert_eq!(queue.len(), 0, "premise: the proof was dropped");
        let lines = logs.lines("holds a seat this node's view");
        eprintln!("REACH seat-hold-owed-named lines={}", lines.len());
        assert_eq!(lines.len(), 1, "premise: one line: {lines:?}");
        let owed = lines[0]
            .split("owed=[")
            .nth(1)
            .and_then(|rest| rest.split(']').next())
            .unwrap_or_default();
        assert!(
            owed.contains(&format!("{}@1495", hex::encode([7u8; 35])))
                && !owed.contains(&hex::encode([9u8; 35]))
                && lines[0].contains(&format!("window_end={window_end}")),
            "OWED-UNNAMED: the line does not name the seat left owed and the window's end: {}",
            lines[0]
        );
    }

    /// Whether the transport gave up the proof `bundle` carries, `why`
    /// ([`super::abandoned`]).
    fn given_up(why: &str, bundle: &[u8]) -> bool {
        let proof = StorageProofSubmission::of(bundle).expect("premise: a storage epoch proof");
        super::abandoned_proofs()
            .lock()
            .unwrap()
            .iter()
            .any(|(said, member, seats)| {
                *said == why && *member == proof.member && *seats == proof.seats
            })
    }

    /// A transport to `archive` (none: no archive), reading `view`.
    async fn transport_to(
        archive: Option<String>,
        view: super::SettledSeat,
    ) -> super::ProdProverMessageTransport {
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(Duration::ZERO));
        if let Some(address) = archive {
            pool.add(address).await;
        }
        super::ProdProverMessageTransport {
            archive_pool: pool,
            clock_store: Arc::new(quil_store::testing::InMemoryClockStore::new()),
            p2p_handle: quil_p2p::node::P2PHandle::for_test(false),
            falcon_signing_key: Some(quil_p2p::generate_falcon_signing_key()),
            publish_to_blossomsub: false,
            retry_queue: Arc::new(SubmitRetryQueue::reading_slots(view)),
            join_header_check: Arc::new(|_: &quil_types::proto::global::GlobalFrame| true),
        }
    }

    /// The transport names a proof's seats as the node's batching stamps
    /// them (`storage_epoch_batch::named_proof_seats`): giving a proof up
    /// takes back only stamps whose seats match exactly.
    #[test]
    fn a_proofs_seats_are_named_as_its_batching_stamps_them() {
        use quil_execution::global_intrinsic::storage_epoch_proof::{SeatProof, StorageEpochProof};
        let part = |shard: u8, epoch: u64, seals: bool, settles: bool| SeatProof {
            shard_filter: vec![shard; 35],
            epoch,
            seals,
            settles,
            ..Default::default()
        };
        let parts = vec![
            part(9, 1495, true, false),
            part(3, 1496, false, true),
            part(5, 1495, true, true),
        ];
        let proof = StorageEpochProof {
            member: [1; 32],
            seats: parts.clone(),
            proof: vec![0x5a; 8],
        };
        let bundle =
            crate::master_node::reward_proofs::prover_bundle(proof.to_canonical_bytes()).unwrap();
        let mut named = StorageProofSubmission::of(&bundle)
            .expect("premise: a storage epoch proof")
            .seats;
        named.sort_unstable();
        let stamped = quil_engine::storage_epoch_batch::named_proof_seats(&parts);
        eprintln!("REACH seat-hold-seats-named equal={}", named == stamped);
        assert_eq!(
            named, stamped,
            "SEATS-MISNAMED: the transport names a proof's seats unlike its batching's stamps"
        );
    }

    /// A queued proof dropped for a seat this node's view shows sealed is
    /// given up: its other seats' retries go at once.
    #[test]
    fn a_queued_proof_dropped_as_settled_is_given_up() {
        let (settled, view) = settled_view();
        let queue = SubmitRetryQueue::reading_slots(view);
        let group = storage_proof_bundle(1, &[(7, 1495, true, false), (9, 1495, true, false)], 8);
        queue.push(group.clone());
        settled.lock().unwrap().sealed.insert((9, 1497));
        queue.drop_settled(FAST, &|| Some(5));
        assert_eq!(queue.len(), 0, "premise: the proof was dropped");
        let given = given_up("settled", &group);
        eprintln!("REACH seat-hold-given-up-dropped given={given}");
        assert!(
            given,
            "KEPT-DROPPED: a queued proof dropped as settled was not given up"
        );
    }

    /// A proof sent again from the queue, taken as one of its seats
    /// settled, is given up: GLOBAL refuses it whole.
    #[tokio::test]
    async fn a_resent_proof_taken_as_its_seat_settled_is_given_up() {
        let (settled, view) = settled_view();
        let queue = Arc::new(SubmitRetryQueue::reading_slots(view));
        let group = storage_proof_bundle(1, &[(10, 1495, true, true), (11, 1495, false, true)], 8);
        queue.push(group.clone());
        let flip = settled.clone();
        run_retries(
            queue.clone(),
            FAST,
            move |_| {
                flip.lock().unwrap().closed.insert((11, 1495));
                async {
                    Delivery {
                        accepted: 1,
                        ..Default::default()
                    }
                }
            },
            || Some(1),
        )
        .await;
        assert_eq!(queue.len(), 0, "premise: an archive took it");
        let given = given_up("settled", &group);
        eprintln!("REACH seat-hold-given-up-resent-settled given={given}");
        assert!(
            given,
            "KEPT-RESENT-SETTLED: a resent proof taken as its seat settled was not given up"
        );
    }

    /// A proof sent again from the queue and refused for good by every
    /// archive is given up.
    #[tokio::test]
    async fn a_resent_proof_every_archive_refuses_for_good_is_given_up() {
        let queue = Arc::new(SubmitRetryQueue::default());
        let proof = storage_proof_bundle(1, &[(12, 1495, false, true)], 8);
        queue.push(proof.clone());
        run_retries(
            queue.clone(),
            FAST,
            |_| async { Delivery::default() },
            || Some(1),
        )
        .await;
        assert_eq!(queue.len(), 0, "premise: it was dropped");
        let given = given_up("refused", &proof);
        eprintln!("REACH seat-hold-given-up-resent-refused given={given}");
        assert!(
            given,
            "KEPT-RESENT-REFUSED: a resent proof refused for good was not given up"
        );
    }

    /// A proof a full retry queue drops is given up.
    #[test]
    fn a_proof_a_full_queue_drops_is_given_up() {
        let queue = SubmitRetryQueue::default();
        let bundles = overfull_queue(1);
        let oldest = bundles[0].clone();
        for bundle in bundles {
            queue.push(bundle);
        }
        assert_eq!(queue.len(), super::RETRY_MAX_MESSAGES, "premise: full");
        let given = given_up("evicted", &oldest);
        eprintln!("REACH seat-hold-given-up-evicted given={given}");
        assert!(
            given,
            "KEPT-EVICTED: a proof a full queue dropped was not given up"
        );
    }

    /// A proof holding a seat this node's view shows settled, not sent, is
    /// given up.
    #[tokio::test]
    async fn a_proof_not_sent_for_a_settled_seat_is_given_up() {
        use quil_engine::prover_message_transport::ProverMessageTransport;
        let (settled, view) = settled_view();
        settled.lock().unwrap().closed.insert((9, 1495));
        let transport = transport_to(None, view).await;
        let group = storage_proof_bundle(1, &[(8, 1495, false, true), (9, 1495, false, true)], 64);
        let _ = transport.publish_prover_bundle(group.clone()).await;
        assert_eq!(transport.retry_queue.len(), 0, "premise: not queued");
        let given = given_up("settled", &group);
        eprintln!("REACH seat-hold-given-up-not-sent given={given}");
        assert!(
            given,
            "KEPT-NOT-SENT: a proof not sent for a settled seat was not given up"
        );
    }

    /// A proof an archive takes as one of its seats settles is given up:
    /// GLOBAL refuses it whole.
    #[tokio::test]
    async fn a_proof_taken_as_its_seat_settled_is_given_up() {
        use quil_engine::prover_message_transport::ProverMessageTransport;
        let (settled, view) = settled_view();
        let flip = settled.clone();
        let handler: quil_rpc::SubmitHandler = Arc::new(move |_request| {
            flip.lock().unwrap().closed.insert((9, 1495));
            Box::pin(async { Ok(()) })
        });
        let transport = transport_to(Some(archive_answering(handler).await), view).await;
        let group = storage_proof_bundle(1, &[(8, 1495, false, true), (9, 1495, false, true)], 64);
        let _ = transport.publish_prover_bundle(group.clone()).await;
        assert!(
            settled.lock().unwrap().closed.contains(&(9, 1495)),
            "premise: the archive took it"
        );
        let given = given_up("settled", &group);
        eprintln!("REACH seat-hold-given-up-taken-settled given={given}");
        assert!(
            given,
            "KEPT-TAKEN-SETTLED: a proof taken as its seat settled was not given up"
        );
    }

    /// A proof every archive refuses for good is given up.
    #[tokio::test]
    async fn a_proof_every_archive_refuses_for_good_is_given_up() {
        use quil_engine::prover_message_transport::ProverMessageTransport;
        let handler: quil_rpc::SubmitHandler = Arc::new(|_request| {
            Box::pin(async { Err(quil_rpc::SubmitRefusal::invalid("invalid proof")) })
        });
        let (_, view) = settled_view();
        let transport = transport_to(Some(archive_answering(handler).await), view).await;
        let proof = storage_proof_bundle(1, &[(13, 1495, false, true)], 64);
        let _ = transport.publish_prover_bundle(proof.clone()).await;
        assert_eq!(transport.retry_queue.len(), 0, "premise: not queued");
        let given = given_up("refused", &proof);
        eprintln!("REACH seat-hold-given-up-refused given={given}");
        assert!(
            given,
            "KEPT-REFUSED: a proof every archive refused for good was not given up"
        );
    }
}

#[cfg(test)]
mod join_header_tests {
    use super::{freshest_verified_header, join_frame_header};
    use quil_types::proto::global::GlobalFrameHeader;

    fn check(accept: bool) -> quil_rpc::frame_sync::FrameValidator {
        std::sync::Arc::new(move |_: &quil_types::proto::global::GlobalFrame| accept)
    }

    fn chosen(
        local: Option<u64>,
        answers: &[(&str, u64)],
        check: &quil_rpc::frame_sync::FrameValidator,
    ) -> Option<(String, u64)> {
        let answers = answers
            .iter()
            .map(|(addr, number)| (addr.to_string(), header(*number)))
            .collect();
        join_frame_header(local.map(header), answers, check).map(|(src, h)| (src, h.frame_number))
    }

    /// R112-D-2: no archive answer lowers the join frame below the local
    /// head, verified or not: a replayed old certified head, frame 0, or a
    /// legacy header signed by a key it carries would make the chain refuse
    /// the join as stale.
    #[test]
    fn r112_d2_an_archive_head_below_the_local_head_does_not_lower_the_join_frame() {
        let accept = check(true);
        assert_eq!(
            chosen(Some(100), &[("replay", 90), ("zero", 0)], &accept),
            Some(("local head".to_string(), 100)),
            "R112-D-2: an archive head below the local head set the join frame"
        );
        assert_eq!(
            chosen(Some(100), &[("replay", 90), ("b", 105)], &accept),
            Some(("b".to_string(), 105))
        );
        assert_eq!(
            chosen(None, &[("b", 7)], &accept),
            Some(("b".to_string(), 7))
        );
        assert_eq!(chosen(None, &[], &accept), None);
    }

    /// R112-D-2: an archive head above the local head sets the join frame
    /// only through the header check; a refused one leaves the local head.
    #[test]
    fn r112_d2_the_join_frame_takes_an_archive_head_only_through_the_check() {
        assert_eq!(
            chosen(Some(100), &[("x", 105)], &check(false)),
            Some(("local head".to_string(), 100)),
            "R112-D-2: an archive head the check refused set the join frame"
        );
        assert_eq!(
            chosen(Some(100), &[("x", 105)], &check(true)),
            Some(("x".to_string(), 105))
        );
    }

    fn header(frame_number: u64) -> GlobalFrameHeader {
        GlobalFrameHeader {
            frame_number,
            ..Default::default()
        }
    }

    /// R112-D-2: a join's frame comes from the freshest archive head header
    /// that verifies. One archive (or whoever answers at its address)
    /// serving an unverifiable header with a far-future frame number would
    /// otherwise stamp every join with it, and the chain refuses each one.
    #[test]
    fn r112_d2_an_unverified_archive_head_does_not_set_the_join_frame() {
        let forged = 4_000_000_000;
        let answers = vec![
            ("a".to_string(), header(100)),
            ("forger".to_string(), header(forged)),
            ("b".to_string(), header(101)),
            ("c".to_string(), header(101)),
        ];
        let chosen = freshest_verified_header(answers.clone(), |h| h.frame_number != forged)
            .map(|(addr, h)| (addr, h.frame_number));
        assert_eq!(
            chosen,
            Some(("b".to_string(), 101)),
            "R112-D-2: the join frame came from an unverified archive head header"
        );
        assert_eq!(
            freshest_verified_header(answers, |_| false).map(|(_, h)| h.frame_number),
            None,
            "R112-D-2: with no verified answer the join takes the local head"
        );
    }
}
