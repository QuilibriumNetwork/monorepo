//! Every signer of a shard frame, kept until a GLOBAL frame carries it.
//!
//! GLOBAL pays the signers a shard frame's certificate names. A certificate is
//! a bitmap and one signature per signer, any quorum of them verifies, and so
//! a holder of any copy can drop signers without a key. A collector that kept
//! the first verified copy of a frame let the copy that arrived first decide
//! who was paid.
//!
//! A collector now holds the union of the valid signatures it sees for a
//! (shard, frame) until a finalized frame carries it. A later copy naming a
//! signer the held one lacks has only those signatures verified, against the
//! committee that certified the held copy, and the held copy takes them. A copy
//! naming no new signer is a duplicate without any verification. A bundle
//! carrying several shard frames, which no honest node sends, is taken apart so
//! that no bundle can stand beside this comparison; each of its frames is
//! admitted alone. Nothing here changes what a certificate must be for anyone
//! to accept it: every build accepts any signer set of at least a quorum.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};

use quil_cw_consensus::app_cert::{self, AddedSigners};
use quil_execution::global_intrinsic::frame_header::{FrameHeader, TYPE_FRAME_HEADER};
use quil_execution::global_intrinsic::handoff;
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

use super::{
    extract_shard_frame_checks, unindex, Candidate, CollectedMessage, MessageCollector, Provenance,
    RankBuffer, RankFullState, Refusal, Reject, RejectKind, Sender, ShardFrame, ShardFrameVerdict,
    SubmitOutcome, MAX_BYTES_PER_RANK, VERIFICATION_WAIT,
};
use crate::proposal_pool::Intake;

/// The committee that signs a session's certificates.
#[derive(Debug, PartialEq, Eq)]
pub struct Committee {
    pub members: Vec<Vec<u8>>,
    pub namespace: Vec<u8>,
}

/// The committee of a shard's session at a generation
/// ([`MessageCollector::set_certificate_committees`]); `None` when only the
/// collector's whole-frame verifier can judge it.
pub type CommitteeSource = Arc<dyn Fn(&[u8], u64) -> Option<Arc<Committee>> + Send + Sync>;

/// Copies whose added signers are verified at once. One forged signature ends
/// a copy's check, so this binds only on a flood.
const MAX_CONCURRENT_UNIONS: usize = 4;

/// Unverified copies of a frame a newly verified copy takes signers from, those
/// naming the most signers first. What it does not reach leaves with the
/// superseded copies; the next copy naming those signers restores them.
const MAX_ABSORBED_COPIES: usize = 8;

/// Sessions [`session_committees`] remembers, the shards of a network several
/// times over.
const MAX_COMMITTEES: usize = 4096;

/// Committees read, by shard filter and generation.
type CommitteeCache = HashMap<(Vec<u8>, u64), Arc<Committee>>;

/// How often the collector's summary of unions is logged.
const UNION_LOG_EVERY: Duration = Duration::from_secs(300);

/// What the collector's unions did since the last summary.
#[derive(Default)]
struct UnionCounts {
    copies_merged: u64,
    signers_added: u64,
    copies_without_new_signer: u64,
    copies_forged: u64,
    copies_busy: u64,
    copies_rank_full: u64,
    bundles_split: u64,
    frames_included: u64,
    frames_included_short: u64,
    signers_left_out: u64,
}

struct UnionLog {
    logged: Instant,
    counts: UnionCounts,
}

/// The collector's state for its unions.
pub(super) struct UnionState {
    committees: RwLock<Option<CommitteeSource>>,
    running: Mutex<usize>,
    ended: Condvar,
    log: Mutex<UnionLog>,
}

impl Default for UnionState {
    fn default() -> Self {
        Self {
            committees: RwLock::new(None),
            running: Mutex::new(0),
            ended: Condvar::new(),
            log: Mutex::new(UnionLog {
                logged: Instant::now(),
                counts: UnionCounts::default(),
            }),
        }
    }
}

/// A place among the unions running at once.
struct UnionSlot<'a>(&'a UnionState);

impl Drop for UnionSlot<'_> {
    fn drop(&mut self) {
        *self.0.running.lock().unwrap() -= 1;
        self.0.ended.notify_one();
    }
}

impl UnionState {
    /// Wait at most [`VERIFICATION_WAIT`] for a place.
    fn slot(&self) -> Option<UnionSlot<'_>> {
        let deadline = Instant::now() + VERIFICATION_WAIT;
        let mut running = self.running.lock().unwrap();
        while *running >= MAX_CONCURRENT_UNIONS {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            running = self.ended.wait_timeout(running, left).unwrap().0;
        }
        *running += 1;
        Some(UnionSlot(self))
    }

    /// Count something; one line per [`UNION_LOG_EVERY`] says what happened.
    fn note(&self, count: impl FnOnce(&mut UnionCounts)) {
        let mut log = self.log.lock().unwrap();
        count(&mut log.counts);
        let now = Instant::now();
        let window = now.duration_since(log.logged);
        if window < UNION_LOG_EVERY {
            return;
        }
        log.logged = now;
        let c = std::mem::take(&mut log.counts);
        drop(log);
        tracing::info!(
            copies_merged = c.copies_merged,
            signers_added = c.signers_added,
            copies_without_new_signer = c.copies_without_new_signer,
            copies_forged = c.copies_forged,
            copies_busy = c.copies_busy,
            copies_rank_full = c.copies_rank_full,
            bundles_split = c.bundles_split,
            frames_included = c.frames_included,
            frames_included_short = c.frames_included_short,
            signers_left_out = c.signers_left_out,
            window_secs = window.as_secs(),
            "message collector: shard frame certificates, counts since the previous line. copies_merged: copies that added signers_added signers to a held frame. copies_forged: copies refused for a signature that does not verify; many from one sender are its problem. copies_busy or copies_rank_full: copies whose signers this archive could not take now; a later copy restores them. frames_included_short: included frames whose copy lacked signers_left_out signers this archive held, which the leader's copy did not have when it proposed or left out"
        );
    }
}

/// Committees from the sessions executed GLOBAL state authorized. A session of
/// a generation never changes, so each is read once. Generation zero stays with
/// the whole-frame verifier, which chooses between a session and a legacy
/// committee.
pub fn session_committees(global: Arc<quil_hypergraph::HypergraphCrdt>) -> CommitteeSource {
    let cache: Mutex<CommitteeCache> = Mutex::new(HashMap::new());
    Arc::new(move |filter, generation| {
        if generation == 0 {
            return None;
        }
        let key = (filter.to_vec(), generation);
        if let Some(committee) = cache.lock().unwrap().get(&key) {
            return Some(Arc::clone(committee));
        }
        let view = crate::app_handoff::committed_view(&global).ok()??;
        let session = handoff::session_at_generation(&view, filter, generation).ok()??;
        let namespace = session.namespace().ok()?;
        let committee = Arc::new(Committee {
            members: session.members,
            namespace,
        });
        remember_committee(&mut cache.lock().unwrap(), key, Arc::clone(&committee));
        Some(committee)
    })
}

fn remember_committee(cache: &mut CommitteeCache, key: (Vec<u8>, u64), committee: Arc<Committee>) {
    if cache.len() >= MAX_COMMITTEES {
        cache.clear();
    }
    cache.insert(key, committee);
}

/// The one shard frame header `data` carries, when its signature field holds a
/// certificate, with the decoded bundle and the header's place in it.
fn certified_header(data: &[u8]) -> Option<(CanonicalMessageBundle, usize, FrameHeader)> {
    let bundle = CanonicalMessageBundle::from_canonical_bytes(data).ok()?;
    let mut headers = bundle
        .requests
        .iter()
        .enumerate()
        .filter_map(|(index, request)| {
            request
                .as_ref()
                .filter(|request| request.inner_type_prefix == TYPE_FRAME_HEADER)
                .map(|request| (index, request))
        });
    let (index, request) = headers.next()?;
    if headers.next().is_some() {
        return None;
    }
    let header = FrameHeader::from_canonical_bytes(&request.inner_bytes).ok()?;
    app_cert::unwrap_cert_from_header(&header.public_key_signature_bls48581)?;
    Some((bundle, index, header))
}

/// How many members a bundle's one certificate names, read from its bitmap and
/// not verified; 0 for anything else. It only orders copies to try.
fn bundle_signers(data: &[u8]) -> usize {
    certified_header(data)
        .and_then(|(_, _, header)| {
            app_cert::unverified_signers(app_cert::unwrap_cert_from_header(
                &header.public_key_signature_bls48581,
            )?)
        })
        .map_or(0, |(_, signers)| signers)
}

/// What a copy holds beside the frame a collector holds.
enum Compared {
    /// Not the same header and proposal apart from its signers.
    Other,
    NoNewSigner,
    Adds(AddedSigners),
}

/// Compare a copy with the held message. The certificate signs the frame's
/// output and the output binds every other header field, so an equal header and
/// proposal mean an equal subject for every signature.
fn compare(held: &[u8], copy: &[u8]) -> Compared {
    let (Some((_, _, mut held)), Some((_, _, mut copy))) =
        (certified_header(held), certified_header(copy))
    else {
        return Compared::Other;
    };
    let held_field = std::mem::take(&mut held.public_key_signature_bls48581);
    let copy_field = std::mem::take(&mut copy.public_key_signature_bls48581);
    if held != copy {
        return Compared::Other;
    }
    let (Some(held_cert), Some(copy_cert)) = (
        app_cert::unwrap_cert_from_header(&held_field),
        app_cert::unwrap_cert_from_header(&copy_field),
    ) else {
        return Compared::Other;
    };
    match app_cert::added_signers(held_cert, copy_cert) {
        None => Compared::Other,
        Some(added) if added.is_empty() => Compared::NoNewSigner,
        Some(added) => Compared::Adds(added),
    }
}

/// The bytes of `held` with `added`'s signers in its certificate; `None` when
/// it holds them all by now.
fn extended(held: &[u8], added: &AddedSigners) -> Option<Vec<u8>> {
    let (mut bundle, index, mut header) = certified_header(held)?;
    let certificate = added.extend(app_cert::unwrap_cert_from_header(
        &header.public_key_signature_bls48581,
    )?)?;
    header.public_key_signature_bls48581 = app_cert::wrap_cert_for_header(&certificate);
    bundle.requests[index] = Some(CanonicalMessageRequest {
        inner_type_prefix: TYPE_FRAME_HEADER,
        inner_bytes: header.to_canonical_bytes().ok()?,
    });
    bundle.to_canonical_bytes().ok()
}

/// A held verified single-shard copy of `address`'s `frame`: its rank and key.
fn held_verified(
    buffers: &HashMap<u64, RankBuffer>,
    address: &[u8],
    frame: u64,
) -> Option<(u64, [u8; 32])> {
    buffers.iter().find_map(|(rank, buffer)| {
        buffer.by_shard.get(address)?.iter().find_map(|key| {
            (buffer.verified.contains(key)
                && buffer.shard_frame(key).is_some_and(|s| s.frame == frame))
            .then_some((*rank, *key))
        })
    })
}

impl RankBuffer {
    /// The message with `key`.
    fn message(&self, key: &[u8; 32]) -> Option<&CollectedMessage> {
        self.messages.get(self.seen.get(key)?)
    }

    /// Put `message` in the place of the message with `key`, keeping its
    /// arrival, unless that takes the rank past its byte cap.
    fn replace(&mut self, key: &[u8; 32], message: CollectedMessage) -> bool {
        let Some(arrival) = self.seen.get(key).copied() else {
            return false;
        };
        let Some(old) = self.messages.get(&arrival) else {
            return false;
        };
        if (self.bytes - old.data.len()).saturating_add(message.data.len()) > MAX_BYTES_PER_RANK {
            return false;
        }
        if let Some(old) = self.messages.remove(&arrival) {
            unindex(
                &mut self.seen,
                &mut self.verified,
                &mut self.by_shard,
                &mut self.bytes,
                &mut self.shares,
                &old,
            );
        }
        self.seen.insert(message.hash, arrival);
        if message.verified {
            self.verified.insert(message.hash);
        }
        if let Some(shard) = &message.shard {
            self.by_shard
                .entry(shard.address.clone())
                .or_default()
                .insert(message.hash);
        }
        self.bytes += message.data.len();
        self.shares.add(&message);
        self.messages.insert(arrival, message);
        true
    }
}

/// The verdict on the signers a copy adds.
enum Judged {
    Valid,
    Forged(String),
    /// Nothing can judge them now.
    Unjudged,
}

impl MessageCollector {
    /// Read the committee of a frame's session from `source`, so a copy's added
    /// signers are verified alone. Without one, or for a generation it does not
    /// name, the whole-frame verifier judges the union.
    pub fn set_certificate_committees(&self, source: CommitteeSource) {
        *self.union.committees.write().unwrap() = Some(source);
    }

    /// Whether admitting `data` verifies signatures, when the union decides:
    /// it names a signer a held copy lacks, or nobody new, or it is a bundle to
    /// take apart. `None` for anything else.
    pub(super) fn union_requires_verification(&self, data: &[u8]) -> Option<bool> {
        self.shard_frame_verifier.read().unwrap().as_ref()?;
        let checks = extract_shard_frame_checks(data);
        match checks.as_slice() {
            [] => None,
            [check] => {
                let buffers = self.buffers.read().unwrap();
                let (rank, key) = held_verified(&buffers, &check.address, check.frame_number)?;
                match compare(&buffers.get(&rank)?.message(&key)?.data, data) {
                    Compared::Other => None,
                    Compared::NoNewSigner => Some(false),
                    Compared::Adds(_) => Some(true),
                }
            }
            _ => Some(true),
        }
    }

    /// Judge `added`, which a copy offers to the frame `held` carries.
    fn judge(
        &self,
        address: &[u8],
        held: &[u8],
        added: &AddedSigners,
        provenance: Provenance,
    ) -> Judged {
        let source = self.union.committees.read().unwrap().clone();
        if let Some(committee) = source.and_then(|source| source(address, added.generation())) {
            return if added.verify(&committee.members, &committee.namespace) {
                Judged::Valid
            } else {
                Judged::Forged("a copy names a signer whose signature does not verify".into())
            };
        }
        let (Some(verify), Some(union)) = (
            self.shard_frame_verifier.read().unwrap().clone(),
            extended(held, added),
        ) else {
            return Judged::Unjudged;
        };
        match verify(&union, provenance) {
            ShardFrameVerdict::Valid => Judged::Valid,
            ShardFrameVerdict::Invalid(reason) => Judged::Forged(reason),
            ShardFrameVerdict::Unavailable(_) | ShardFrameVerdict::Full(_) => Judged::Unjudged,
        }
    }

    /// Take `message`'s signers into the held verified copy of its frame.
    /// `None` when there is none, or nothing judges them now: admission goes on
    /// as for any other message.
    pub(super) fn union_copy(
        &self,
        message: &CollectedMessage,
        provenance: Provenance,
    ) -> Option<SubmitOutcome> {
        let shard = message.shard.as_ref()?;
        self.shard_frame_verifier.read().unwrap().as_ref()?;
        let held = {
            let buffers = self.buffers.read().unwrap();
            let (rank, key) = held_verified(&buffers, &shard.address, shard.frame)?;
            if key == message.hash {
                return None;
            }
            buffers.get(&rank)?.message(&key)?.data.clone()
        };
        let added = match compare(&held, &message.data) {
            Compared::Other => return None,
            Compared::NoNewSigner => {
                self.union.note(|c| c.copies_without_new_signer += 1);
                return Some(SubmitOutcome::Duplicate);
            }
            Compared::Adds(added) => added,
        };
        let Some(_slot) = self.union.slot() else {
            self.union.note(|c| c.copies_busy += 1);
            return Some(SubmitOutcome::Duplicate);
        };
        match self.judge(&shard.address, &held, &added, provenance) {
            Judged::Valid => {}
            Judged::Unjudged => return None,
            Judged::Forged(reason) => {
                self.union.note(|c| c.copies_forged += 1);
                self.note_reject(
                    Instant::now(),
                    Reject {
                        kind: RejectKind::Verification,
                        address: shard.address.clone(),
                        frame_number: shard.frame,
                        valid_shard_count: self.valid_shard_addresses.read().unwrap().len(),
                        refresh: self.refresh_state(),
                        reason,
                    },
                );
                self.intake.note(Intake::RefusedInvalid, Instant::now());
                return Some(SubmitOutcome::Filtered(Refusal::InvalidShardFrame));
            }
        }
        Some(self.file_union(shard, &added))
    }

    /// Put verified `added` into the held copy as it is now: other copies may
    /// have added to it since `added` was compared.
    fn file_union(&self, shard: &ShardFrame, added: &AddedSigners) -> SubmitOutcome {
        let mut buffers = self.buffers.write().unwrap();
        // A finalized frame carrying it took the held copy under this lock.
        let Some((rank, key)) = held_verified(&buffers, &shard.address, shard.frame) else {
            return SubmitOutcome::Duplicate;
        };
        let ranks_held = buffers.len();
        let Some(buffer) = buffers.get_mut(&rank) else {
            return SubmitOutcome::Duplicate;
        };
        let Some(mut union) = buffer
            .message(&key)
            .and_then(|held| Some(held.with_signers(extended(&held.data, added)?)))
        else {
            return SubmitOutcome::Duplicate;
        };
        union.verified = true;
        let union_key = union.hash;
        if buffer.replace(&key, union) {
            // Under the buffers' lock, as admission checks the claims: no
            // shield of a coin the held copy claimed may come in between.
            self.shield_claims.lock().unwrap().rekey(&key, union_key);
            drop(buffers);
            self.intake.note(Intake::Accepted, Instant::now());
            let added = added.len() as u64;
            self.union.note(|c| {
                c.copies_merged += 1;
                c.signers_added += added;
            });
            return SubmitOutcome::Accepted;
        }
        self.intake.note(Intake::RefusedRankFull, Instant::now());
        self.note_rank_full(
            Instant::now(),
            RankFullState {
                rank,
                pending: buffer.len(),
                pending_bytes: buffer.bytes,
                ranks_held,
            },
        );
        drop(buffers);
        self.union.note(|c| c.copies_rank_full += 1);
        SubmitOutcome::Filtered(Refusal::RankFull)
    }

    /// `message` was just verified and will supersede the unverified copies of
    /// its frame: take their valid signers first.
    pub(super) fn absorb_unverified(&self, message: &mut CollectedMessage, provenance: Provenance) {
        let Some(shard) = message.shard.clone() else {
            return;
        };
        let mut sources: Vec<Vec<u8>> = Vec::new();
        {
            let buffers = self.buffers.read().unwrap();
            for buffer in buffers.values() {
                for key in buffer.by_shard.get(&shard.address).into_iter().flatten() {
                    if buffer.verified.contains(key)
                        || buffer
                            .shard_frame(key)
                            .is_none_or(|s| s.frame != shard.frame)
                    {
                        continue;
                    }
                    if let Some(source) = buffer.message(key) {
                        sources.push(source.data.clone());
                    }
                }
            }
        }
        if sources.is_empty() {
            return;
        }
        sources.sort_by_cached_key(|source| std::cmp::Reverse(bundle_signers(source)));
        sources.truncate(MAX_ABSORBED_COPIES);
        let Some(_slot) = self.union.slot() else {
            self.union.note(|c| c.copies_busy += sources.len() as u64);
            return;
        };
        let mut union = message.data.clone();
        for source in &sources {
            let Compared::Adds(added) = compare(&union, source) else {
                continue;
            };
            match self.judge(&shard.address, &union, &added, provenance) {
                Judged::Valid => {
                    if let Some(extended) = extended(&union, &added) {
                        union = extended;
                        let added = added.len() as u64;
                        self.union.note(|c| {
                            c.copies_merged += 1;
                            c.signers_added += added;
                        });
                    }
                }
                Judged::Forged(_) => self.union.note(|c| c.copies_forged += 1),
                Judged::Unjudged => {}
            }
        }
        if union == message.data {
            return;
        }
        *message = message.with_signers(union);
        message.verified = true;
        // A source of the same bytes would make this one a duplicate of a copy
        // still held unverified.
        let mut buffers = self.buffers.write().unwrap();
        for buffer in buffers.values_mut() {
            buffer.take(&message.hash);
        }
        buffers.retain(|_, buffer| !buffer.is_empty());
    }

    /// Admit each shard frame of a bundle alone, and what else it carries as one
    /// message. The first forged frame ends it: the bundle costs no more
    /// verification than one judged whole. A frame that must wait says so to
    /// the sender, which sends the bundle again.
    pub(super) fn admit_parts(
        &self,
        rank: u64,
        data: &[u8],
        provenance: Provenance,
        sender: Sender<'_>,
    ) -> SubmitOutcome {
        let Ok(bundle) = CanonicalMessageBundle::from_canonical_bytes(data) else {
            return SubmitOutcome::Filtered(Refusal::InvalidShardFrame);
        };
        self.union.note(|c| c.bundles_split += 1);
        let timestamp = bundle.timestamp;
        let (headers, others): (Vec<_>, Vec<_>) = bundle.requests.into_iter().partition(|r| {
            r.as_ref()
                .is_some_and(|r| r.inner_type_prefix == TYPE_FRAME_HEADER)
        });
        let others = (!others.is_empty()).then_some(others);
        let (mut accepted, mut refused) = (false, None);
        for requests in headers.into_iter().map(|r| vec![r]).chain(others) {
            let part = CanonicalMessageBundle {
                requests,
                timestamp,
            }
            .to_canonical_bytes();
            let Ok(part) = part else {
                return SubmitOutcome::Filtered(Refusal::InvalidShardFrame);
            };
            match self.admit(rank, part, false, provenance, sender) {
                SubmitOutcome::Accepted => accepted = true,
                SubmitOutcome::Duplicate => {}
                SubmitOutcome::Filtered(Refusal::InvalidShardFrame) => {
                    return SubmitOutcome::Filtered(Refusal::InvalidShardFrame);
                }
                SubmitOutcome::Filtered(refusal) => refused = Some(refusal),
            }
        }
        match refused {
            Some(refusal) if refusal.retryable() || !accepted => SubmitOutcome::Filtered(refusal),
            _ if accepted => SubmitOutcome::Accepted,
            _ => SubmitOutcome::Duplicate,
        }
    }

    /// Count, of the frames a finalized frame carries, those whose copy lacks
    /// signers the copy held here has: what a leader's choice or a late copy
    /// left unpaid.
    pub(super) fn note_included(&self, raw_msgs: &[Vec<u8>]) {
        if self.shard_frame_verifier.read().unwrap().is_none() {
            return;
        }
        let (mut frames, mut short, mut left_out) = (0, 0, 0);
        {
            let buffers = self.buffers.read().unwrap();
            for raw in raw_msgs {
                let checks = extract_shard_frame_checks(raw);
                let [check] = checks.as_slice() else {
                    continue;
                };
                frames += 1;
                let held = held_verified(&buffers, &check.address, check.frame_number)
                    .and_then(|(rank, key)| buffers.get(&rank)?.message(&key));
                if let Some(Compared::Adds(added)) = held.map(|held| compare(raw, &held.data)) {
                    short += 1;
                    left_out += added.len() as u64;
                }
            }
        }
        if frames > 0 {
            self.union.note(|c| {
                c.frames_included += frames;
                c.frames_included_short += short;
                c.signers_left_out += left_out;
            });
        }
    }
}

/// Copies of one frame a proposal may copy, those naming the most signers
/// first; the sort is stable, so arrival order stands among equals.
pub(super) fn most_signers_first(candidates: &mut [Candidate<'_>]) {
    if candidates.len() > 1 {
        candidates.sort_by_cached_key(|c| std::cmp::Reverse(bundle_signers(&c.2.data)));
    }
}

/// Order the shard proofs a leader picks tips from so that, among one frame's
/// copies, the one naming the most signers is tried first
/// ([`crate::leader_provider::select_shard_tips`] keeps this order within a
/// frame). It matters for copies no collector could verify on arrival, which it
/// could not take the union of either.
pub(crate) fn order_copies_by_signers(messages: &mut [Vec<u8>]) {
    messages.sort_by_cached_key(|raw| std::cmp::Reverse(bundle_signers(raw)));
}

#[cfg(test)]
#[path = "cert_union_tests.rs"]
mod tests;
