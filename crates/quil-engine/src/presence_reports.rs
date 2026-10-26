//! Presence reports this node submits for its running committee session
//! ([`quil_execution::global_intrinsic::handoff::presence`]).
//!
//! A session below quorum finalizes nothing, so GLOBAL cannot see which of
//! its members still vote. While the session's committed GLOBAL tip stands
//! still, one member carries the notarize votes it received to GLOBAL: up to
//! four recent proposals it built or verified, chosen to cover the most
//! members, with one vote per member and 64 in all. The trigger is GLOBAL's
//! own committed stall signal, not local quorum, so a committee that
//! finalizes frames locally whose headers never reach GLOBAL reports too:
//! GLOBAL then learns which of its members are present.
//!
//! Who submits. A member verifies each notarize vote it holds once
//! ([`VoteChecks`]) and orders the members whose votes it verified by a key
//! drawn from the session and the epoch; only the first submits
//! ([`designated_submitter`]). Members that see one another's votes agree on
//! it, and a vote that does not verify can neither make its signer the
//! submitter nor keep another member from it. A designated member that does
//! not submit (offline, or unable to reach GLOBAL) loses its committee that
//! epoch's report; the order changes every epoch.
//!
//! Nullify votes. From the presence exclusion frame a report also carries
//! verified nullify votes ([`build_with_nullifies`]) of members its notarize
//! votes leave out, and nullify voters count among the verified voters the
//! submitter is drawn from. Stalled sessions' members often only nullify;
//! a nullify protects its signer from exclusion for absence and earns no
//! credit. Liveness keeps nullify signatures with the notarize ones.
//!
//! Traffic bound. Nothing is built before the presence report frame, in an
//! epoch's last [`Pace::margin_frames`], or for a session whose tip advanced
//! in the last [`Pace::stall_frames`]. A submitter sends at most
//! [`MAX_REPORTS_PER_EPOCH`] reports per session and epoch,
//! [`Pace::resubmit_frames`] apart, a later one only when it covers members its
//! earlier ones did not. Members that verified the same voters agree on one
//! submitter, so a committee whose members all reach one another sends at
//! most 3 reports per stalled session and epoch. A partitioned committee, or
//! one whose members see different voters, has one submitter per distinct
//! view of the voters: at worst, with every member alone, 3 × members
//! reports per session and epoch, each carrying only its sender's vote. A
//! report is at most 4 headers and 64 votes of 670 bytes, about 45 KB.
//!
//! Peak per GLOBAL frame. Every schedule starts over with the epoch, so
//! without a spread the designated members of all stalled sessions would
//! submit in the epoch's first frames, together with its confirmations. A
//! session's first report of an epoch therefore waits for a frame drawn from
//! the session within the first quarter of the epoch
//! ([`Pace::first_frame`]), and its later ones follow at least
//! [`Pace::resubmit_frames`] after. With 100 stalled sessions on mainnet,
//! about 0.6 first reports land per GLOBAL frame over 180 frames, and a frame
//! rarely gets more than 4: at most about 180 KB, 256 Falcon verifications
//! and 16 frame-output recomputations for every node that materializes it,
//! typically one report of about 20 KB with 25 verifications.
//!
//! Nothing is kept while the presence report frame is unset (mainnet, and
//! by default): consensus then copies no vote signature
//! ([`Liveness::keep_votes`]), no session is looked at, and the master
//! relays no worker's report. Once the frame is set, votes are kept and
//! sessions looked at even before it is reached; reports wait for it.
//!
//! A report whose publication fails or is held back (a coverage halt, an
//! unreachable master or transport) gives its budget back
//! ([`publication_failed`]): the next look may build it again.
//!
//! Cost on this node. A member looks again only every [`Pace::check_frames`]
//! committed GLOBAL frames, verifies each vote once, copies only the
//! signatures it has not checked, and reads proposal bodies only when it is
//! the submitter and a report is due.
//!
//! Known limits. A look runs on the engine's loop: once reports are active
//! it captures the committed view on every tick before its cheap gates, and
//! a member's first look at a full session verifies up to 16 views × 64
//! members of votes inline. The schedule lives in memory, so a submitter
//! restarted mid-epoch may send up to its budget again (still spread and
//! spaced). No line marks the end of a stall, hold or wait: the next line
//! is a submission, or none once the session's tip moves again.

use std::collections::{BTreeMap, BTreeSet};

use quil_cw_consensus::adapters::{Liveness, NotarizeKey, NotarizedProposal, NullifyKey};
use quil_cw_consensus::handoff::{Seal, Session, SessionVotes};
use quil_execution::global_intrinsic::frame_header::FrameHeader;
use quil_execution::global_intrinsic::handoff::{
    self,
    presence::{NotarizeVote, NullifyVote, PresenceProposal, PresenceReport, MAX_PRESENCE_PROPOSALS, MAX_PRESENCE_VOTES},
    Records,
};
use quil_types::consensus::epoch_length_frames;
use quil_types::error::{QuilError, Result};
use sha2::{Digest as _, Sha256};

/// Reports this node submits per session and epoch.
pub const MAX_REPORTS_PER_EPOCH: u32 = 3;

/// A refusal is logged at the first of an epoch and then at every this many.
pub const REFUSALS_LOGGED_EVERY: u32 = 4;

/// Presence reports this process failed to publish, by the SHA-256 of their
/// bytes, for the reporter that built them to give back their budget. The
/// publish paths that can tell (a thread worker's, in its master; a
/// standalone worker's, from its master's answer) run in the reporter's
/// process. Bounded: an entry the reporter never claims is dropped.
static UNPUBLISHED: std::sync::Mutex<std::collections::VecDeque<[u8; 32]>> =
    std::sync::Mutex::new(std::collections::VecDeque::new());
const MAX_UNPUBLISHED: usize = 16;

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Note that the GLOBAL request `request` was not published; for a presence
/// report, its reporter gives back the budget it used.
pub fn publication_failed(request: &[u8]) {
    if !request.starts_with(&quil_execution::global_intrinsic::handoff::TYPE_PRESENCE_REPORT.to_be_bytes()) {
        return;
    }
    let Ok(mut failed) = UNPUBLISHED.lock() else { return };
    if failed.len() >= MAX_UNPUBLISHED {
        failed.pop_front();
    }
    failed.push_back(digest(request));
}

fn take_unpublished(hash: &[u8; 32]) -> bool {
    let Ok(mut failed) = UNPUBLISHED.lock() else { return false };
    let before = failed.len();
    failed.retain(|entry| entry != hash);
    failed.len() != before
}

/// Recent eligible proposals one report is chosen from.
const MAX_CANDIDATES: usize = 8;

/// The pacing of presence reports, from one reading of the epoch length,
/// so one look never mixes two (testnets and tests switch it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pace {
    /// GLOBAL frames per epoch.
    pub length: u64,
}

impl Pace {
    pub fn current() -> Self {
        Self { length: epoch_length_frames() }
    }

    pub fn epoch(&self, frame: u64) -> u64 {
        frame / self.length
    }

    /// GLOBAL frames a session's committed tip must have stood still before
    /// its members report presence: a twelfth of an epoch, 60 on mainnet.
    pub fn stall_frames(&self) -> u64 {
        (self.length / 12).max(1)
    }

    /// GLOBAL frames between two reports of this node for one session.
    pub fn resubmit_frames(&self) -> u64 {
        self.stall_frames()
    }

    /// Committed GLOBAL frames between two looks at a stalled session's
    /// votes: 3 on mainnet, at least 2.
    pub fn check_frames(&self) -> u64 {
        (self.length / 240).max(2)
    }

    /// Frames before an epoch ends in which no report is built: it could
    /// land in the next epoch, where its anchors are refused. 30 on mainnet.
    pub fn margin_frames(&self) -> u64 {
        (self.length / 24).max(1)
    }

    /// Frames at the start of an epoch over which sessions' first reports
    /// are spread: a quarter of an epoch, 180 on mainnet.
    pub fn spread_frames(&self) -> u64 {
        (self.length / 4).max(1)
    }

    /// The first GLOBAL frame of `epoch` a report of session `id` may be
    /// built for: the epoch's start plus an offset drawn from the session
    /// within [`Self::spread_frames`].
    pub fn first_frame(&self, id: &[u8; 32], epoch: u64) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(b"quil/presence-report/first-frame");
        hasher.update(id);
        let digest: [u8; 32] = hasher.finalize().into();
        let offset = u64::from_be_bytes(digest[..8].try_into().expect("8 bytes")) % self.spread_frames();
        epoch.saturating_mul(self.length).saturating_add(offset)
    }

    /// The first GLOBAL frame of `epoch` a member `member` of session `id`
    /// that the epoch's reports left out may report itself for: the epoch's
    /// second half, after the designated submitter's turns, plus an offset
    /// drawn from the session and member within a quarter epoch, so the
    /// left-out members do not all report at once.
    pub fn self_report_frame(&self, id: &[u8; 32], epoch: u64, member: u32) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(b"quil/presence-report/self-report");
        hasher.update(id);
        hasher.update(epoch.to_be_bytes());
        hasher.update(member.to_be_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let offset = u64::from_be_bytes(digest[..8].try_into().expect("8 bytes")) % self.spread_frames();
        epoch.saturating_mul(self.length).saturating_add(self.length / 2).saturating_add(offset)
    }

    /// Whether a report may land in GLOBAL frame `frame`: from `activation`
    /// on, and not in the last [`Self::margin_frames`] of its epoch.
    pub fn window_open(&self, frame: u64, activation: u64) -> bool {
        frame >= activation && self.length - frame % self.length > self.margin_frames()
    }
}

/// Of the members whose votes this node verified, the one that submits
/// `session`'s report in `epoch`: the first in an order drawn from the
/// session and the epoch, so one member reports for its committee, and a
/// different one each epoch.
pub fn designated_submitter(session: &[u8; 32], epoch: u64, voters: &BTreeSet<u32>) -> Option<u32> {
    voters.iter().copied().min_by_key(|signer| {
        let mut hasher = Sha256::new();
        hasher.update(b"quil/presence-report/submitter");
        hasher.update(session);
        hasher.update(epoch.to_be_bytes());
        hasher.update(signer.to_be_bytes());
        let key: [u8; 32] = hasher.finalize().into();
        key
    })
}

/// Where the notarize votes of the running session come from: its
/// [`Liveness`], or a test's.
pub trait VoteSource {
    /// [`Liveness::notarize_votes`].
    fn notarize_votes(&self, wanted: &dyn Fn(&NotarizeKey) -> bool) -> Vec<(NotarizeKey, Option<Vec<u8>>)>;
    /// [`Liveness::notarized`].
    fn notarized(&self) -> Vec<NotarizedProposal>;
    /// [`Liveness::nullify_votes`]; none unless the source keeps them.
    fn nullify_votes(&self, _wanted: &dyn Fn(&NullifyKey) -> bool) -> Vec<(NullifyKey, Option<Vec<u8>>)> {
        Vec::new()
    }
}

impl VoteSource for Liveness {
    fn notarize_votes(&self, wanted: &dyn Fn(&NotarizeKey) -> bool) -> Vec<(NotarizeKey, Option<Vec<u8>>)> {
        Liveness::notarize_votes(self, wanted)
    }

    fn notarized(&self) -> Vec<NotarizedProposal> {
        Liveness::notarized(self)
    }

    fn nullify_votes(&self, wanted: &dyn Fn(&NullifyKey) -> bool) -> Vec<(NullifyKey, Option<Vec<u8>>)> {
        Liveness::nullify_votes(self, wanted)
    }
}

/// Whether each notarize vote this node holds for its running session
/// verifies. Consensus checks votes only in batches, once a certificate
/// could form, so a stalled session's votes may never be checked; here each
/// is verified once, and its result kept while the vote stays in the recent
/// views.
#[derive(Debug, Default)]
pub struct VoteChecks {
    session: [u8; 32],
    results: BTreeMap<NotarizeKey, bool>,
    /// Whether each nullify vote verifies ([`Self::refresh_nullifies`]).
    nullify_results: BTreeMap<NullifyKey, bool>,
    /// Falcon verifications done.
    verifications: u64,
}

impl VoteChecks {
    /// Check the votes of session `id` that `source` holds: each vote not
    /// checked before is verified, and the results of votes `source` no
    /// longer holds are dropped.
    pub fn refresh(&mut self, id: [u8; 32], checker: &SessionVotes, source: &dyn VoteSource) {
        if self.session != id {
            self.session = id;
            self.results.clear();
            self.nullify_results.clear();
        }
        let votes = {
            let results = &self.results;
            source.notarize_votes(&|key| !results.contains_key(key))
        };
        let mut results = BTreeMap::new();
        for (key, signature) in votes {
            let valid = match (self.results.get(&key), signature) {
                (Some(valid), _) => *valid,
                (None, Some(signature)) => {
                    self.verifications += 1;
                    checker.verify_notarize(key.epoch, key.view, key.parent, key.payload, key.signer, &signature)
                }
                (None, None) => continue,
            };
            results.insert(key, valid);
        }
        self.results = results;
    }

    /// Check the nullify votes `source` holds of the session last
    /// [`Self::refresh`]ed, as that checks notarize votes: each once, and
    /// the results of votes no longer held dropped.
    pub fn refresh_nullifies(&mut self, checker: &SessionVotes, source: &dyn VoteSource) {
        let votes = {
            let results = &self.nullify_results;
            source.nullify_votes(&|key| !results.contains_key(key))
        };
        let mut results = BTreeMap::new();
        for (key, signature) in votes {
            let valid = match (self.nullify_results.get(&key), signature) {
                (Some(valid), _) => *valid,
                (None, Some(signature)) => {
                    self.verifications += 1;
                    checker.verify_nullify(key.epoch, key.view, key.signer, &signature)
                }
                (None, None) => continue,
            };
            results.insert(key, valid);
        }
        self.nullify_results = results;
    }

    /// Whether the nullify vote was checked and verifies.
    pub fn valid_nullify(&self, key: &NullifyKey) -> bool {
        self.nullify_results.get(key).copied().unwrap_or(false)
    }

    /// The members whose nullify votes of `session`'s generation verify.
    pub fn nullify_voters(&self, session: &Session) -> BTreeSet<u32> {
        self.nullify_results
            .iter()
            .filter(|(key, valid)| {
                **valid && key.epoch == session.generation && (key.signer as usize) < session.members.len()
            })
            .map(|(key, _)| key.signer)
            .collect()
    }

    /// Whether the vote was checked and verifies.
    pub fn valid(&self, key: &NotarizeKey) -> bool {
        self.results.get(key).copied().unwrap_or(false)
    }

    /// The members whose notarize votes of `session`'s generation verify.
    pub fn voters(&self, session: &Session) -> BTreeSet<u32> {
        self.results
            .iter()
            .filter(|(key, valid)| {
                **valid && key.epoch == session.generation && (key.signer as usize) < session.members.len()
            })
            .map(|(key, _)| key.signer)
            .collect()
    }

    /// Falcon verifications done so far.
    pub fn verifications(&self) -> u64 {
        self.verifications
    }
}

/// A report and the members whose votes it carries.
#[derive(Debug)]
pub struct Built {
    pub report: PresenceReport,
    pub members: BTreeSet<u32>,
}

impl Built {
    pub fn views(&self) -> Vec<u64> {
        self.report.proposals.iter().map(|proposal| proposal.view).collect()
    }
}

/// Build a report of `session` (ID `id`) for inclusion in GLOBAL frame
/// `inclusion` from the notarize votes `seen`
/// ([`quil_cw_consensus::adapters::Liveness::notarized`]), keeping only the
/// votes `valid` says verify: one bad vote makes GLOBAL refuse the whole
/// report. It carries proposals of the session's generation, anchored
/// earlier in `inclusion`'s epoch, whose body this node sealed, of the
/// latest [`MAX_CANDIDATES`]. Proposals are taken while they add members,
/// the one adding the most first (the later on a tie), one per view, with
/// one vote per member, within [`MAX_PRESENCE_PROPOSALS`] and
/// [`MAX_PRESENCE_VOTES`].
pub fn build(
    session: &Session,
    id: [u8; 32],
    pace: Pace,
    inclusion: u64,
    seen: &[NotarizedProposal],
    valid: impl Fn(&NotarizeKey) -> bool,
) -> Option<Built> {
    build_with_nullifies(session, id, pace, inclusion, seen, valid, Vec::new())
}

/// [`build`], then the verified nullify votes `nullifies` (one per member,
/// in ascending signer order) of the members its notarize votes left out,
/// within [`MAX_PRESENCE_VOTES`]. A nullify protects its signer from
/// exclusion for absence and earns nothing. With no notarize vote to carry,
/// the report carries nullifies alone: a session whose members only
/// nullify (no proposal reached them, or none they accept) still shows who
/// follows it.
pub fn build_with_nullifies(
    session: &Session,
    id: [u8; 32],
    pace: Pace,
    inclusion: u64,
    seen: &[NotarizedProposal],
    valid: impl Fn(&NotarizeKey) -> bool,
    nullifies: Vec<NullifyVote>,
) -> Option<Built> {
    // Latest first.
    let mut candidates: Vec<PresenceProposal> = eligible(session, pace, inclusion, seen)
        .map(|(seen, header)| PresenceProposal {
            header,
            epoch: seen.epoch,
            view: seen.view,
            parent: seen.parent,
            payload: seen.payload,
            votes: seen
                .votes
                .iter()
                .filter(|(signer, _)| valid(&key(seen, *signer)))
                .map(|(signer, signature)| NotarizeVote { signer: *signer, signature: signature.clone() })
                .collect(),
        })
        .collect();
    let mut members = BTreeSet::new();
    let mut chosen = Vec::new();
    while chosen.len() < MAX_PRESENCE_PROPOSALS && members.len() < MAX_PRESENCE_VOTES {
        let gain = |candidate: &PresenceProposal| {
            candidate.votes.iter().filter(|vote| !members.contains(&vote.signer)).count()
        };
        let mut best: Option<(usize, usize)> = None;
        for (index, candidate) in candidates.iter().enumerate() {
            let added = gain(candidate);
            if added > 0 && best.is_none_or(|(_, most)| added > most) {
                best = Some((index, added));
            }
        }
        let Some((index, _)) = best else { break };
        let mut proposal = candidates.remove(index);
        // Views ascend strictly in a report: another proposal of the same
        // view (an equivocating leader) cannot join this one.
        candidates.retain(|candidate| candidate.view != proposal.view);
        proposal.votes.retain(|vote| !members.contains(&vote.signer));
        proposal.votes.truncate(MAX_PRESENCE_VOTES - members.len());
        members.extend(proposal.votes.iter().map(|vote| vote.signer));
        chosen.push(proposal);
    }
    chosen.sort_by_key(|proposal| proposal.view);
    let room = MAX_PRESENCE_VOTES.saturating_sub(members.len());
    let nullifies: Vec<NullifyVote> =
        nullifies.into_iter().filter(|vote| !members.contains(&vote.signer)).take(room).collect();
    members.extend(nullifies.iter().map(|vote| vote.signer));
    if chosen.is_empty() && nullifies.is_empty() {
        return None;
    }
    Some(Built {
        report: PresenceReport { session: id, filter: session.filter.clone(), proposals: chosen, nullifies },
        members,
    })
}

/// Of the nullify votes `source` holds, the verified ones of `session`'s
/// generation, the latest view of each member, in ascending signer order.
/// Only views above `floor`, the highest GLOBAL recorded in earlier epochs
/// ([`handoff::presence::nullify_floor`]), are taken: GLOBAL refuses the rest.
fn verified_nullifies(session: &Session, checks: &VoteChecks, source: &dyn VoteSource, floor: u64) -> Vec<NullifyVote> {
    let mut latest: BTreeMap<u32, NullifyVote> = BTreeMap::new();
    for (key, signature) in source.nullify_votes(&|key| checks.valid_nullify(key)) {
        let Some(signature) = signature else { continue };
        if key.epoch != session.generation || key.view <= floor || (key.signer as usize) >= session.members.len() {
            continue;
        }
        if latest.get(&key.signer).is_none_or(|kept| kept.view < key.view) {
            latest.insert(key.signer, NullifyVote { view: key.view, signer: key.signer, signature });
        }
    }
    latest.into_values().collect()
}

fn key(seen: &NotarizedProposal, signer: u32) -> NotarizeKey {
    NotarizeKey { epoch: seen.epoch, view: seen.view, parent: seen.parent, payload: seen.payload, signer }
}

/// The proposals in `seen` a report for inclusion in `inclusion` could
/// carry, latest first, with their headers.
fn eligible<'a>(
    session: &'a Session,
    pace: Pace,
    inclusion: u64,
    seen: &'a [NotarizedProposal],
) -> impl Iterator<Item = (&'a NotarizedProposal, FrameHeader)> + 'a {
    seen.iter()
        .rev()
        .filter_map(move |seen| Some((seen, header(session, seen).filter(|header| anchored_in(pace, header, inclusion))?)))
        .take(MAX_CANDIDATES)
}

/// The canonical header of a sealed app frame body of `session` at the
/// proposal's view, without the certificate and storage openings a report
/// must not carry.
fn header(session: &Session, seen: &NotarizedProposal) -> Option<FrameHeader> {
    if seen.epoch != session.generation || seen.view == 0 || seen.parent >= seen.view || Seal::is_encoding(&seen.body) {
        return None;
    }
    let frame = <quil_types::proto::global::AppShardFrame as prost::Message>::decode(seen.body.as_slice()).ok()?;
    let mut header = quil_execution::global_intrinsic::conversions::frame_header_from_proto(frame.header.as_ref()?);
    header.public_key_signature_bls48581.clear();
    header.storage_attestation.clear();
    let matches = header.address == session.filter
        && header.rank == seen.view
        && header.frame_number > session.base_frame
        && quil_crypto::poseidon::hash_bytes_to_32(&header.output).ok() == Some(seen.payload);
    matches.then_some(header)
}

/// Whether GLOBAL accepts the header's anchor in a report included in
/// `inclusion`: an earlier frame of the same epoch.
fn anchored_in(pace: Pace, header: &FrameHeader, inclusion: u64) -> bool {
    let anchor = header.global_frame_number;
    anchor != 0 && anchor < inclusion && pace.epoch(anchor) == pace.epoch(inclusion)
}

/// Why a designated member found no proposal to report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ineligible {
    /// Proposals of the recent views whose body this node sealed.
    pub sealed: usize,
    /// Of those, frames of the session anchored at or after the inclusion
    /// frame: this node's committed GLOBAL view trails the anchors its
    /// committee uses.
    pub anchored_ahead: usize,
    /// Frames of the session anchored before the inclusion epoch, or at no
    /// frame.
    pub anchored_before: usize,
    /// Eligible proposals without a vote this node verified.
    pub unverified: usize,
}

fn ineligible(
    session: &Session,
    pace: Pace,
    inclusion: u64,
    seen: &[NotarizedProposal],
    valid: &dyn Fn(&NotarizeKey) -> bool,
) -> Ineligible {
    let mut why = Ineligible { sealed: seen.len(), ..Ineligible::default() };
    for seen in seen {
        let Some(header) = header(session, seen) else { continue };
        if anchored_in(pace, &header, inclusion) {
            if !seen.votes.iter().any(|(signer, _)| valid(&key(seen, *signer))) {
                why.unverified += 1;
            }
        } else if header.global_frame_number >= inclusion {
            why.anchored_ahead += 1;
        } else {
            why.anchored_before += 1;
        }
    }
    why
}

/// Why a stalled session's report is not built now, though one is due.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hold {
    /// The report would land in the last [`Pace::margin_frames`] of its
    /// epoch, or in the next: it could arrive after the epoch ends, when its
    /// anchors are refused. Ends with the epoch.
    EpochEnd { landing: u64 },
    /// This node's committed GLOBAL view trails the latest GLOBAL frame it
    /// holds into another epoch, so a report checked against the view could
    /// land in a later epoch than its anchors. Ends when the view catches up.
    ViewBehind { latest: u64 },
}

impl Hold {
    fn cause(&self) -> &'static str {
        match self {
            Self::EpochEnd { .. } => "epoch end",
            Self::ViewBehind { .. } => "view behind",
        }
    }
}

/// An expected wait the local check of a built report runs into before any
/// vote is verified. Each names the event that ends it ([`Wait::ends`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// This node's committed GLOBAL view does not hold the session yet.
    UnknownSession,
    /// The session is no longer the current head of its filter: a successor
    /// was activated.
    Superseded,
    /// The session is closed.
    Closed,
    /// This node lacks the output of GLOBAL frame `anchor`, a proposal's
    /// anchor.
    Anchor { anchor: u64 },
    /// GLOBAL already recorded every member the report carries present for
    /// this epoch, so it would refuse the report
    /// ([`handoff::presence::marks_new_member`]).
    Recorded,
}

impl Wait {
    pub fn cause(&self) -> &'static str {
        match self {
            Self::UnknownSession => "session not in this node's committed GLOBAL view",
            Self::Superseded => "session superseded by a successor",
            Self::Closed => "session closed",
            Self::Anchor { .. } => "anchor GLOBAL frame missing from this node's stores",
            Self::Recorded => "every member carried is already recorded present this epoch",
        }
    }

    /// The event that ends the wait.
    pub fn ends(&self) -> &'static str {
        match self {
            Self::UnknownSession => "this node's GLOBAL view materializes the session",
            Self::Superseded | Self::Closed => "this node's host retires the session",
            Self::Anchor { .. } => "this worker syncs the anchor GLOBAL frame",
            Self::Recorded => "a member GLOBAL has not recorded present this epoch votes, or the epoch ends",
        }
    }
}

/// What one look at the running session ([`PresenceReporter::attempt`])
/// found, past the quiet gates.
#[derive(Debug)]
pub enum Outcome {
    /// The session stalled, but no report is built now.
    Held(Hold),
    /// The session stalled, and another member submits: `designated`, the
    /// first of the `voters` whose votes this node verified (`None` while
    /// it verified none).
    NotDesignated { designated: Option<u32>, voters: usize },
    /// This node submits, but no recent proposal can be reported.
    NothingEligible(Ineligible),
    /// An expected wait: the report is not checked or sent yet.
    Wait(Wait),
    /// The report fails the check GLOBAL applies although no expected wait
    /// explains it: a signature, header output or encoding this node built
    /// disagrees with GLOBAL's rules, a defect.
    /// `refusals`: this epoch's so far, the first in `since` (an inclusion
    /// frame).
    Refused { built: Built, error: QuilError, refusals: u32, since: u64 },
    /// The report passes the check GLOBAL applies: submit `bytes`.
    Submit { built: Built, bytes: Vec<u8>, added: usize, voters: usize },
}

/// One look at a stalled session.
#[derive(Debug)]
pub struct Attempt {
    pub session: [u8; 32],
    pub epoch: u64,
    /// The GLOBAL frame a report is checked for: the frame after this
    /// node's committed view.
    pub inclusion: u64,
    /// GLOBAL frames since the session's committed tip last advanced.
    pub stalled: u64,
    pub outcome: Outcome,
    /// Whether to log the outcome: always a submission; a refusal at the
    /// first and every [`REFUSALS_LOGGED_EVERY`]th of an epoch; any other
    /// outcome once per cause, session and epoch.
    pub log: bool,
}

/// This node's reports of its running session in the current epoch.
#[derive(Debug, Default)]
pub struct PresenceSchedule {
    session: [u8; 32],
    epoch: u64,
    /// Members the epoch's submitted reports carried.
    reported: BTreeSet<u32>,
    submitted: u32,
    /// The inclusion frame of the last report submitted, refused or found
    /// to add nobody.
    last: Option<u64>,
    /// The committed GLOBAL frame of the last look at the session's votes.
    looked: Option<u64>,
    /// Outcomes logged this epoch, by cause.
    noted: BTreeSet<&'static str>,
    /// Reports the local check refused this epoch, and the inclusion frame
    /// of the first.
    refusals: u32,
    first_refused: Option<u64>,
    /// The last submission's bytes digest and the members reported before
    /// it, to give its budget back if it was not published.
    pending: Option<([u8; 32], BTreeSet<u32>, bool)>,
    /// The inclusion frame this member last reported itself for this epoch.
    self_reported: Option<u64>,
}

impl PresenceSchedule {
    /// Start over for another session or epoch.
    pub fn observe(&mut self, session: [u8; 32], epoch: u64) {
        if (self.session, self.epoch) != (session, epoch) {
            *self = Self { session, epoch, ..Self::default() };
        }
    }

    /// Whether to look at the session's votes at committed GLOBAL frame
    /// `frame`: `every` frames after the last look. A look is recorded.
    pub fn look(&mut self, frame: u64, every: u64) -> bool {
        if self.looked.is_some_and(|last| frame < last.saturating_add(every)) {
            return false;
        }
        self.looked = Some(frame);
        true
    }

    /// Whether a report may be built for inclusion in `inclusion`, `spacing`
    /// frames after the last.
    pub fn due(&self, inclusion: u64, spacing: u64) -> bool {
        self.submitted < MAX_REPORTS_PER_EPOCH
            && self.last.is_none_or(|last| inclusion >= last.saturating_add(spacing))
    }

    /// How many of `members` the epoch's submitted reports did not carry.
    pub fn adds(&self, members: &BTreeSet<u32>) -> usize {
        members.difference(&self.reported).count()
    }

    pub fn submitted(&mut self, inclusion: u64, members: &BTreeSet<u32>) {
        self.submitted += 1;
        self.last = Some(inclusion);
        self.reported.extend(members);
    }

    /// Record the bytes of the submission just counted, so that
    /// [`Self::reclaim`] can give it back.
    fn pending(&mut self, bytes: &[u8], reported_before: BTreeSet<u32>, alone: bool) {
        self.pending = Some((digest(bytes), reported_before, alone));
    }

    /// Give back the budget of the last submission if its publication
    /// failed ([`publication_failed`]): it no longer counts, nor do the
    /// members it carried. Its spacing still holds.
    fn reclaim(&mut self) {
        if let Some((hash, before, alone)) = self.pending.take() {
            if take_unpublished(&hash) {
                self.submitted = self.submitted.saturating_sub(1);
                self.reported = before;
                if alone {
                    self.self_reported = None;
                }
            } else {
                self.pending = Some((hash, before, alone));
            }
        }
    }

    /// A report built for `inclusion` adds no member.
    pub fn idle(&mut self, inclusion: u64) {
        self.last = Some(inclusion);
    }

    /// The local check refused a report built for `inclusion`: this
    /// epoch's refusals so far, and the inclusion frame of the first.
    pub fn refused(&mut self, inclusion: u64) -> (u32, u64) {
        self.last = Some(inclusion);
        self.refusals += 1;
        (self.refusals, *self.first_refused.get_or_insert(inclusion))
    }

    /// True the first time `cause` is noted this session and epoch.
    pub fn note(&mut self, cause: &'static str) -> bool {
        self.noted.insert(cause)
    }
}

/// What a look at the running session is given.
pub struct Look<'a, R: Records> {
    /// This node's committed GLOBAL view, and its frame.
    pub view: &'a R,
    pub frame: u64,
    /// The latest GLOBAL frame this node holds, if known.
    pub latest: Option<u64>,
    pub session: &'a Session,
    /// This node's key among the session's members.
    pub key: &'a [u8],
    pub pace: Pace,
}

/// Presence reports of this node's running session: when to look, which
/// votes verify, and what was sent this epoch.
#[derive(Debug, Default)]
pub struct PresenceReporter {
    schedule: PresenceSchedule,
    checks: VoteChecks,
    /// Calls of [`Self::attempt`].
    attempts: u64,
}

impl PresenceReporter {
    /// Look at the running session, every [`Pace::check_frames`] committed
    /// GLOBAL frames while its tip stands still. `None` when there is
    /// nothing to say: reports inactive, this node not a member, the
    /// session's [`Pace::first_frame`] of the epoch not reached, the tip
    /// advanced recently, the last look or report too recent, or a report
    /// that adds nobody. `anchor_output` returns a GLOBAL frame's output from this
    /// node's stores. A submission is recorded as sent.
    pub fn attempt<R: Records>(
        &mut self,
        look: Look<'_, R>,
        source: &dyn VoteSource,
        anchor_output: impl Fn(u64) -> Result<Vec<u8>>,
    ) -> Option<Attempt> {
        self.attempts += 1;
        let (activation, pace) = (handoff::presence_report_frame(), look.pace);
        let session = look.session;
        let id = session.id().ok()?;
        let me = session.members.binary_search_by(|member| member.as_slice().cmp(look.key)).ok()? as u32;
        // The report lands in a later GLOBAL frame than the one viewed.
        let inclusion = look.frame.saturating_add(1);
        let epoch = pace.epoch(inclusion);
        self.schedule.observe(id, epoch);
        self.schedule.reclaim();
        // Sessions' first reports of an epoch are spread over its first
        // quarter, apart from the epoch's confirmations.
        if inclusion < activation
            || inclusion < pace.first_frame(&id, epoch)
            || !self.schedule.look(look.frame, pace.check_frames())
        {
            return None;
        }
        let stalled = handoff::frames_since_tip_advance(look.view, &id, look.frame).ok()??;
        if stalled < pace.stall_frames() || !self.schedule.due(inclusion, pace.resubmit_frames()) {
            return None;
        }
        // `log`: the outcome is a submission or refusal, or the first of its
        // cause this epoch.
        let attempt = |outcome: Outcome, log: bool| Some(Attempt { session: id, epoch, inclusion, stalled, outcome, log });
        // It lands no earlier than after the latest GLOBAL frame this node
        // holds.
        let latest = look.latest.unwrap_or(look.frame).max(look.frame);
        let landing = latest.saturating_add(1);
        let held = if pace.epoch(landing) != epoch {
            Some(Hold::ViewBehind { latest })
        } else if !pace.window_open(landing, activation) {
            Some(Hold::EpochEnd { landing })
        } else {
            None
        };
        if let Some(hold) = held {
            return attempt(Outcome::Held(hold), self.schedule.note(hold.cause()));
        }
        let checker = SessionVotes::new(session).ok()?;
        self.checks.refresh(id, &checker, source);
        // From the presence exclusion frame nullify votes count too: they
        // protect their signers from exclusion, and a session whose members
        // only nullify has no notarize to report.
        let nullifying = inclusion >= handoff::presence_exclusion_frame();
        let mut voters = self.checks.voters(session);
        if nullifying {
            self.checks.refresh_nullifies(&checker, source);
            voters.extend(self.checks.nullify_voters(session));
        }
        let designated = designated_submitter(&id, epoch, &voters);
        // GLOBAL's records are kept by its own epoch of the inclusion frame.
        let global_epoch = quil_types::consensus::epoch_for_frame(inclusion);
        // One reporter's view must not decide who is absent: from its own
        // frame of the epoch's second half, a member GLOBAL has not recorded
        // present reports its own votes, again every resubmit spacing while
        // GLOBAL still has no record of it (a report lost on the way, or
        // dropped from a mempool), within the epoch's report budget, and at
        // once again if its publication failed. GLOBAL's new-mark rule
        // bounds what that costs.
        let alone = designated != Some(me)
            && nullifying
            && inclusion >= pace.self_report_frame(&id, epoch, me)
            && self.schedule.self_reported.is_none_or(|at| inclusion >= at.saturating_add(pace.resubmit_frames()))
            && !handoff::presence::recorded(look.view, session, global_epoch, me).unwrap_or(true);
        if designated != Some(me) && !alone {
            let outcome = Outcome::NotDesignated { designated, voters: voters.len() };
            // With no vote verified, this node cannot tell who submits.
            let cause = if designated.is_some() { "not designated" } else { "no verified vote" };
            return attempt(outcome, self.schedule.note(cause));
        }
        let seen = source.notarized();
        let checks = &self.checks;
        let valid = |key: &NotarizeKey| checks.valid(key) && (!alone || key.signer == me);
        let nullifies = if nullifying {
            let floor = handoff::presence::nullify_floor(look.view, session, global_epoch).unwrap_or(0);
            let mut nullifies = verified_nullifies(session, &self.checks, source, floor);
            if alone {
                nullifies.retain(|vote| vote.signer == me);
            }
            nullifies
        } else {
            Vec::new()
        };
        let Some(built) = build_with_nullifies(session, id, pace, inclusion, &seen, valid, nullifies) else {
            let why = ineligible(session, pace, inclusion, &seen, &valid);
            return attempt(Outcome::NothingEligible(why), self.schedule.note("nothing eligible"));
        };
        let added = self.schedule.adds(&built.members);
        // A member reporting itself again while GLOBAL has no record of it
        // repeats its own vote: it adds nobody to this node's reports.
        if added == 0 && !alone {
            self.schedule.idle(inclusion);
            return None;
        }
        let outputs = match waits(look.view, inclusion, &id, session, &built.report, &anchor_output) {
            Ok(outputs) => outputs,
            Err(wait) => {
                return attempt(Outcome::Wait(wait), self.schedule.note(wait.cause()));
            }
        };
        // GLOBAL checks the report it decodes from the bytes sent, so those
        // are checked here too.
        let checked = built.report.to_canonical_bytes().and_then(|bytes| {
            let decoded = PresenceReport::from_canonical_bytes(&bytes)?;
            handoff::presence::verify(look.view, inclusion, &decoded, |anchor| {
                outputs
                    .get(&anchor)
                    .cloned()
                    .ok_or_else(|| QuilError::ExecutionUnavailable(format!("anchor {anchor} not fetched")))
            })?;
            Ok(bytes)
        });
        match checked {
            Ok(bytes) => {
                let before = self.schedule.reported.clone();
                if alone {
                    self.schedule.self_reported = Some(inclusion);
                }
                self.schedule.submitted(inclusion, &built.members);
                self.schedule.pending(&bytes, before, alone);
                attempt(Outcome::Submit { built, bytes, added, voters: voters.len() }, true)
            }
            Err(error) => {
                let (refusals, since) = self.schedule.refused(inclusion);
                let log = refusals == 1 || refusals % REFUSALS_LOGGED_EVERY == 0;
                attempt(Outcome::Refused { built, error, refusals, since }, log)
            }
        }
    }

    /// Falcon verifications of notarize votes done so far.
    pub fn verifications(&self) -> u64 {
        self.checks.verifications()
    }

    /// Calls of [`Self::attempt`] so far.
    pub fn attempts(&self) -> u64 {
        self.attempts
    }
}

/// The expected waits of GLOBAL's check of `report` for inclusion in GLOBAL
/// frame `inclusion` ([`handoff::presence::verify`]): the session as head of
/// its filter and not closed in `view`, a member the epoch's presence record
/// lacks, and every anchor's output at hand, which it returns. What remains
/// for the check to refuse is a defect of the report.
fn waits(
    view: &impl Records,
    inclusion: u64,
    id: &[u8; 32],
    session: &Session,
    report: &PresenceReport,
    anchor_output: &dyn Fn(u64) -> Result<Vec<u8>>,
) -> std::result::Result<BTreeMap<u64, Vec<u8>>, Wait> {
    let committed = handoff::session(view, id).ok().flatten().ok_or(Wait::UnknownSession)?;
    if handoff::head(view, &session.filter).ok().flatten().as_ref() != Some(&committed) {
        return Err(Wait::Superseded);
    }
    if matches!(handoff::status(view, id), Ok(handoff::Status::Closed(_))) {
        return Err(Wait::Closed);
    }
    if !handoff::presence::marks_new_member(view, inclusion, &committed, report).unwrap_or(true) {
        return Err(Wait::Recorded);
    }
    let mut outputs = BTreeMap::new();
    for proposal in &report.proposals {
        let anchor = proposal.header.global_frame_number;
        if !outputs.contains_key(&anchor) {
            outputs.insert(anchor, anchor_output(anchor).map_err(|_| Wait::Anchor { anchor })?);
        }
    }
    Ok(outputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_cw_consensus::{
        _consensus::{
            simplex::{scheme::Namespace, types::{Proposal, Subject}},
            types::{Epoch, Round, View},
        },
        _crypto::{sha256::Digest, Signer as _},
        _utils::ordered::Set,
        falcon_base::FalconPrivateKey,
        falcon_scheme::Generic,
        falcon_simplex::SimplexFalconScheme,
    };
    use quil_types::crypto::Signer as _;
    use std::cell::Cell;
    use std::sync::Arc;

    /// The reporter is given this pace, so no test reads the process-wide
    /// epoch length, which other tests switch. GLOBAL's own check reads it,
    /// so every frame below lies in one epoch under both this length and
    /// mainnet's: 7_200 to 7_259.
    const PACE: Pace = Pace { length: 60 };

    /// An inclusion frame early in its epoch, with an anchor before it in
    /// the same epoch and one in the epoch before.
    const INCLUSION: u64 = 7_205;
    const ANCHOR: u64 = 7_203;
    const STALE: u64 = 7_199;

    /// The output of GLOBAL frame `frame` in these tests' stores.
    fn anchor_output(frame: u64) -> Vec<u8> {
        vec![(frame % 251) as u8 + 1; 516]
    }

    fn anchors(frame: u64) -> Result<Vec<u8>> {
        Ok(anchor_output(frame))
    }

    /// Reports are active for the test's thread, and inactive again after.
    struct Active;

    impl Active {
        fn new() -> Self {
            handoff::set_presence_report_frame_for_thread(Some(0));
            Self
        }
    }

    impl Drop for Active {
        fn drop(&mut self) {
            handoff::set_presence_report_frame_for_thread(Some(u64::MAX));
        }
    }

    struct Committee {
        keys: Vec<FalconPrivateKey>,
        session: Session,
        id: [u8; 32],
    }

    /// A first-generation session of `size` members whose keys are in member
    /// order, so a key's index is its signer index.
    fn committee(size: usize) -> Committee {
        let mut keys: Vec<FalconPrivateKey> = (0..size)
            .map(|_| {
                let key = quil_crypto::FalconSigner::generate();
                FalconPrivateKey::from_bytes(key.private_key(), key.public_key()).unwrap()
            })
            .collect();
        keys.sort_by_key(|key| key.public_key().as_ref().to_vec());
        let session = Session {
            chain_id: [0x21; 32],
            filter: vec![0x61; 32],
            generation: 1,
            genesis: quil_crypto::poseidon::hash_bytes_to_32(&[0; 32]).unwrap(),
            base_frame: 10,
            authorization: [0x34; 32],
            members: keys.iter().map(|key| key.public_key().as_ref().to_vec()).collect(),
        };
        let id = session.id().unwrap();
        Committee { keys, session, id }
    }

    impl Committee {
        /// A sealed proposal of the session at `view` anchored at `anchor`,
        /// with notarize votes of `signers`, as the session's liveness
        /// returns it. Its output is the one its producer stamps and GLOBAL
        /// recomputes from the anchor's output.
        fn seen(&self, view: u64, anchor: u64, signers: &[usize]) -> NotarizedProposal {
            self.seen_in(&self.session, view, anchor, signers, view as u8)
        }

        fn seen_in(&self, signing: &Session, view: u64, anchor: u64, signers: &[usize], salt: u8) -> NotarizedProposal {
            let mut header = quil_types::proto::global::FrameHeader {
                address: self.session.filter.clone(),
                frame_number: self.session.base_frame + view,
                rank: view,
                difficulty: 100,
                parent_selector: vec![salt; 32],
                global_frame_number: anchor,
                // Enters the output, unlike the openings a report leaves out.
                storage_attestation_root: vec![0x5a; 32],
                ..Default::default()
            };
            let h = quil_execution::global_intrinsic::conversions::frame_header_from_proto(&header);
            let beacon = quil_crypto::porep::derive_storage_beacon(anchor, &anchor_output(anchor));
            header.output = quil_crypto::porep::deterministic_app_frame_output(
                &h.parent_selector, &h.requests_root, &h.state_roots, &beacon, h.frame_number, h.rank, &h.prover,
                h.difficulty, h.fee_multiplier_vote as u64, h.timestamp, &h.storage_attestation_root,
                h.fee_total_value(), &h.settlements, &h.accumulator, &h.spends,
            );
            let payload = quil_crypto::poseidon::hash_bytes_to_32(&header.output).unwrap();
            let body = prost::Message::encode_to_vec(&quil_types::proto::global::AppShardFrame {
                header: Some(header),
                ..Default::default()
            });
            let participants: Set<_> =
                self.keys.iter().map(|key| key.public_key()).collect::<Vec<_>>().try_into().unwrap();
            let proposal = Proposal::new(
                Round::new(Epoch::new(self.session.generation), View::new(view)),
                View::new(view - 1),
                Digest(payload),
            );
            let mut votes: Vec<(u32, Vec<u8>)> = signers
                .iter()
                .map(|&signer| {
                    let scheme: Generic<Namespace> =
                        Generic::signer(&signing.namespace().unwrap(), participants.clone(), self.keys[signer].clone())
                            .unwrap();
                    let vote = scheme.sign::<SimplexFalconScheme, Digest>(Subject::Notarize { proposal: &proposal }).unwrap();
                    assert_eq!(vote.signer.get() as usize, signer);
                    (vote.signer.get(), vote.signature.get().unwrap().to_vec())
                })
                .collect();
            votes.sort_by_key(|(signer, _)| *signer);
            NotarizedProposal { epoch: self.session.generation, view, parent: view - 1, payload, votes, body }
        }

        /// Member `signer`'s nullify of `view` under the session's namespace,
        /// as the session's liveness keeps it.
        fn nullify(&self, view: u64, signer: usize) -> (NullifyKey, Vec<u8>) {
            let participants: Set<_> =
                self.keys.iter().map(|key| key.public_key()).collect::<Vec<_>>().try_into().unwrap();
            let scheme: Generic<Namespace> =
                Generic::signer(&self.session.namespace().unwrap(), participants, self.keys[signer].clone()).unwrap();
            let round = Round::new(Epoch::new(self.session.generation), View::new(view));
            let vote = scheme.sign::<SimplexFalconScheme, Digest>(Subject::Nullify { round }).unwrap();
            assert_eq!(vote.signer.get() as usize, signer);
            let key = NullifyKey { epoch: self.session.generation, view, signer: vote.signer.get() };
            (key, vote.signature.get().unwrap().to_vec())
        }

        /// A look by `member` at committed GLOBAL frame `frame`, the latest
        /// this node holds.
        fn look<'a, R: Records>(&'a self, view: &'a R, member: usize, frame: u64) -> Look<'a, R> {
            Look {
                view, frame, latest: Some(frame), session: &self.session, key: &self.session.members[member],
                pace: PACE,
            }
        }

        /// The member that submits this epoch when `voters` vote.
        fn designated(&self, voters: &[u32]) -> u32 {
            let voters: BTreeSet<u32> = voters.iter().copied().collect();
            designated_submitter(&self.id, PACE.epoch(INCLUSION), &voters).unwrap()
        }

        /// An inclusion frame of the session in [`INCLUSION`]'s epoch, past
        /// its [`Pace::first_frame`], and an anchor before it.
        fn inclusion(&self) -> u64 {
            PACE.first_frame(&self.id, PACE.epoch(INCLUSION)) + 5
        }

        fn anchor(&self) -> u64 {
            self.inclusion() - 2
        }
    }

    /// A GLOBAL state that holds the session as its filter's head.
    struct Global {
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        _db: quil_store::RocksDb,
    }

    impl Global {
        fn new(session: &Session) -> Self {
            let db = quil_store::RocksDb::open_in_memory().unwrap();
            let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
                Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
                Arc::new(quil_hypergraph::testing::StubProver),
            ));
            crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
            let state = quil_execution::hypergraph_state::HypergraphState::new(crdt.clone());
            handoff::initialize(&state, 2, session).unwrap();
            state.commit().unwrap();
            state.abort();
            crdt.commit_with_global_cursor(2, &quil_store::encoding::global_materialized_cursor_key()).unwrap();
            Self { crdt, _db: db }
        }

        fn view(&self) -> handoff::CommittedView {
            handoff::CommittedView::capture(&self.crdt).unwrap()
        }
    }

    /// A session's notarize votes, counting what is read from them.
    #[derive(Default)]
    struct Votes {
        proposals: Vec<NotarizedProposal>,
        /// Kept nullify votes and their signatures.
        nullifies: Vec<(NullifyKey, Vec<u8>)>,
        /// Lists of votes taken, signatures copied, and body reads.
        listed: Cell<u32>,
        copied: Cell<u32>,
        bodies: Cell<u32>,
    }

    impl Votes {
        fn of(proposals: Vec<NotarizedProposal>) -> Self {
            Self { proposals, ..Self::default() }
        }

        fn reads(&self) -> (u32, u32, u32) {
            (self.listed.get(), self.copied.get(), self.bodies.get())
        }
    }

    impl VoteSource for Votes {
        fn notarize_votes(&self, wanted: &dyn Fn(&NotarizeKey) -> bool) -> Vec<(NotarizeKey, Option<Vec<u8>>)> {
            self.listed.set(self.listed.get() + 1);
            let mut votes = Vec::new();
            for proposal in &self.proposals {
                for (signer, signature) in &proposal.votes {
                    let key = key(proposal, *signer);
                    let copy = wanted(&key);
                    self.copied.set(self.copied.get() + copy as u32);
                    votes.push((key, copy.then(|| signature.clone())));
                }
            }
            votes
        }

        fn notarized(&self) -> Vec<NotarizedProposal> {
            self.bodies.set(self.bodies.get() + 1);
            self.proposals.clone()
        }

        fn nullify_votes(&self, wanted: &dyn Fn(&NullifyKey) -> bool) -> Vec<(NullifyKey, Option<Vec<u8>>)> {
            self.nullifies.iter().map(|(key, signature)| (*key, wanted(key).then(|| signature.clone()))).collect()
        }
    }

    fn checked(c: &Committee, seen: &[NotarizedProposal]) -> VoteChecks {
        let mut checks = VoteChecks::default();
        checks.refresh(c.id, &SessionVotes::new(&c.session).unwrap(), &Votes::of(seen.to_vec()));
        checks
    }

    /// [`build`] for `inclusion` from the votes of `seen` that verify.
    fn build_checked(c: &Committee, inclusion: u64, seen: &[NotarizedProposal]) -> Option<Built> {
        let checks = checked(c, seen);
        build(&c.session, c.id, PACE, inclusion, seen, |key| checks.valid(key))
    }

    fn signers(proposal: &PresenceProposal) -> Vec<u32> {
        proposal.votes.iter().map(|vote| vote.signer).collect()
    }

    #[test]
    fn a_report_covers_the_most_members_with_one_vote_each() {
        let c = committee(5);
        let seen = vec![
            c.seen(5, ANCHOR, &[0, 1]),
            c.seen(6, ANCHOR, &[1, 2, 3]),
            c.seen(7, ANCHOR, &[0, 2]),
            c.seen(8, ANCHOR, &[2]),
        ];
        let built = build_checked(&c, INCLUSION, &seen).unwrap();
        // View 6 adds three members. Then views 5 and 7 each add member 0,
        // and the later is taken without member 2's second vote; view 8 adds
        // nobody.
        assert_eq!(built.views(), vec![6, 7]);
        assert_eq!(signers(&built.report.proposals[0]), vec![1, 2, 3]);
        assert_eq!(signers(&built.report.proposals[1]), vec![0], "one vote per member");
        assert_eq!(built.members, BTreeSet::from([0, 1, 2, 3]));
        assert_eq!(built.report.session, c.id);
        // The codec accepts it: ascending views, one vote per member.
        let bytes = built.report.to_canonical_bytes().unwrap();
        assert_eq!(PresenceReport::from_canonical_bytes(&bytes).unwrap(), built.report);
        assert!(built.report.proposals.iter().all(|p| p.header.public_key_signature_bls48581.is_empty()
            && p.header.storage_attestation.is_empty()));
        // At most four proposals, though a fifth would add a member.
        let seen: Vec<_> = (0..5).map(|member| c.seen(5 + member as u64, ANCHOR, &[member])).collect();
        let built = build_checked(&c, INCLUSION, &seen).unwrap();
        assert_eq!(built.report.proposals.len(), MAX_PRESENCE_PROPOSALS);
        assert_eq!(built.members.len(), MAX_PRESENCE_PROPOSALS);
    }

    #[test]
    fn forged_votes_and_foreign_proposals_are_left_out() {
        let c = committee(4);
        let mut forged = c.seen(5, ANCHOR, &[0, 1]);
        forged.votes[1].1[20] ^= 1;
        let mut other = c.session.clone();
        other.generation += 1;
        let foreign_namespace = c.seen_in(&other, 6, ANCHOR, &[2], 6);
        let mut other_generation = c.seen(7, ANCHOR, &[3]);
        other_generation.epoch += 1;
        let mut seal = c.seen(8, ANCHOR, &[3]);
        let checkpoint = quil_cw_consensus::handoff::Checkpoint {
            frame: 17, view: 7, digest: [2; 32], state_roots: [[3; 32]; 4], history_root: [4; 32],
        };
        seal.body = Seal { request: [1; 32], session: c.id, view: 8, checkpoint }.encode();
        let seen = [forged, foreign_namespace, other_generation, seal];
        let built = build_checked(&c, INCLUSION, &seen).unwrap();
        assert_eq!(built.members, BTreeSet::from([0]), "only member 0's vote is a valid notarize of a session frame");
        assert_eq!(checked(&c, &seen).voters(&c.session), BTreeSet::from([0, 3]), "votes that verify, of the generation");
        // Two proposals of one view: the report carries one of them.
        let equivocated = vec![c.seen_in(&c.session, 9, ANCHOR, &[0, 1], 1), c.seen_in(&c.session, 9, ANCHOR, &[2, 3], 2)];
        let built = build_checked(&c, INCLUSION, &equivocated).unwrap();
        assert_eq!(built.report.proposals.len(), 1);
        assert_eq!(built.members.len(), 2);
    }

    #[test]
    fn anchors_outside_the_inclusion_epoch_are_left_out() {
        let c = committee(4);
        let seen = vec![
            c.seen(5, STALE, &[0]),
            c.seen(6, INCLUSION, &[1]),
            c.seen(7, 0, &[2]),
            c.seen(8, ANCHOR, &[3]),
        ];
        let built = build_checked(&c, INCLUSION, &seen).unwrap();
        assert_eq!(built.members, BTreeSet::from([3]));
        assert!(build_checked(&c, INCLUSION, &seen[..3]).is_none(), "nothing to report");
        let checks = checked(&c, &seen);
        assert_eq!(
            ineligible(&c.session, PACE, INCLUSION, &seen[..3], &|key| checks.valid(key)),
            Ineligible { sealed: 3, anchored_ahead: 1, anchored_before: 2, unverified: 0 },
        );
        assert_eq!(
            ineligible(&c.session, PACE, INCLUSION, &seen, &|_| false),
            Ineligible { sealed: 4, anchored_ahead: 1, anchored_before: 2, unverified: 1 },
        );
    }

    /// The biggest gap of a builder checked only against itself: a report
    /// built from real frame outputs passes the check GLOBAL applies, and
    /// the reporter submits exactly such bytes.
    #[test]
    fn a_built_report_passes_the_check_global_applies() {
        let _active = Active::new();
        let c = committee(4);
        let global = Global::new(&c.session);
        let view = global.view();
        let (inclusion, anchor) = (c.inclusion(), c.anchor());
        let seen = vec![c.seen(5, anchor, &[0, 1]), c.seen(6, anchor - 1, &[1, 2, 3])];
        let built = build_checked(&c, inclusion, &seen).unwrap();
        handoff::presence::verify(&view, inclusion, &built.report, anchors).unwrap();
        // A different anchor output fails GLOBAL's recomputation.
        assert!(handoff::presence::verify(&view, inclusion, &built.report, |frame| anchors(frame + 1)).is_err());
        let votes = Votes::of(seen);
        let me = c.designated(&[0, 1, 2, 3]) as usize;
        let mut reporter = PresenceReporter::default();
        let attempt = reporter.attempt(c.look(&view, me, inclusion - 1), &votes, anchors).unwrap();
        assert!(attempt.log);
        assert_eq!((attempt.inclusion, attempt.epoch, attempt.session), (inclusion, PACE.epoch(inclusion), c.id));
        let (built, bytes, added, voters) = match attempt.outcome {
            Outcome::Submit { built, bytes, added, voters } => (built, bytes, added, voters),
            other => panic!("{other:?}"),
        };
        assert_eq!((added, voters), (4, 4));
        let report = PresenceReport::from_canonical_bytes(&bytes).unwrap();
        assert_eq!(report, built.report);
        handoff::presence::verify(&view, inclusion, &report, anchors).unwrap();
        // It adds nobody later this epoch: nothing more is sent or logged.
        assert!(reporter.attempt(c.look(&view, me, inclusion - 1 + PACE.resubmit_frames()), &votes, anchors).is_none());
    }

    /// A session whose members only nullify (no proposal reaches quorum, or
    /// none is made) reports their verified nullifies from the presence
    /// exclusion frame, and GLOBAL accepts the report; a forged nullify is
    /// left out. Before the frame its members verified no vote.
    #[test]
    fn a_session_that_only_nullifies_reports_its_nullifies_from_the_exclusion_frame() {
        let _active = Active::new();
        let c = committee(5);
        let global = Global::new(&c.session);
        let view = global.view();
        let mut forged = c.nullify(1, 3);
        forged.1[20] ^= 1;
        let votes = Votes { nullifies: vec![c.nullify(1, 0), c.nullify(1, 1), c.nullify(2, 1), c.nullify(1, 2), forged], ..Votes::default() };
        let frame = c.inclusion() - 1;
        let me = c.designated(&[0, 1, 2]) as usize;
        handoff::set_presence_exclusion_frame_for_thread(Some(u64::MAX));
        let attempt = PresenceReporter::default().attempt(c.look(&view, me, frame), &votes, anchors).unwrap();
        assert!(matches!(attempt.outcome, Outcome::NotDesignated { designated: None, voters: 0 }), "{attempt:?}");
        handoff::set_presence_exclusion_frame_for_thread(Some(0));
        let attempt = PresenceReporter::default().attempt(c.look(&view, me, frame), &votes, anchors).unwrap();
        let (built, bytes, voters) = match attempt.outcome {
            Outcome::Submit { built, bytes, voters, .. } => (built, bytes, voters),
            other => panic!("{other:?}"),
        };
        handoff::set_presence_exclusion_frame_for_thread(None);
        assert_eq!(voters, 3);
        assert!(built.report.proposals.is_empty());
        let carried: Vec<(u32, u64)> = built.report.nullifies.iter().map(|vote| (vote.signer, vote.view)).collect();
        assert_eq!(carried, vec![(0, 1), (1, 2), (2, 1)], "each member's latest verified nullify");
        assert_eq!(built.members, BTreeSet::from([0, 1, 2]));
        handoff::set_presence_exclusion_frame_for_thread(Some(0));
        handoff::presence::verify(&view, c.inclusion(), &PresenceReport::from_canonical_bytes(&bytes).unwrap(), anchors)
            .unwrap();
        handoff::set_presence_exclusion_frame_for_thread(None);
    }

    /// A member that is not the designated submitter, and that GLOBAL has
    /// not recorded present, reports its own vote from its own frame of the
    /// epoch's second half (spread by member), again every resubmit spacing
    /// while GLOBAL still has no record of it, with its budget given back
    /// when publication fails, and no more once GLOBAL records it.
    #[test]
    fn an_unrecorded_member_reports_itself_late_in_the_epoch_until_recorded() {
        let _active = Active::new();
        handoff::set_presence_exclusion_frame_for_thread(Some(0));
        let c = committee(5);
        let global = Global::new(&c.session);
        let view = global.view();
        let votes = Votes { nullifies: (0..5).map(|member| c.nullify(1, member)).collect(), ..Votes::default() };
        let epoch = PACE.epoch(INCLUSION);
        let designated = c.designated(&[0, 1, 2, 3, 4]);
        let own = |member: u32| PACE.self_report_frame(&c.id, epoch, member);
        let me = (0..5).filter(|member| *member != designated).min_by_key(|member| own(*member)).unwrap();
        let frames: BTreeSet<u64> = (0..5).map(own).collect();
        assert!(frames.len() > 1, "members are spread");
        let start = epoch * PACE.length;
        assert!(frames.iter().all(|frame| (start + PACE.length / 2..start + 3 * PACE.length / 4).contains(frame)));
        let me_index = me as usize;
        let mut reporter = PresenceReporter::default();
        // Before its own frame it defers to the designated submitter.
        let early = reporter.attempt(c.look(&view, me_index, own(me) - 3), &votes, anchors).unwrap();
        assert!(matches!(early.outcome, Outcome::NotDesignated { .. }), "{early:?}");
        let submitted = |attempt: Option<Attempt>| match attempt.map(|attempt| attempt.outcome) {
            Some(Outcome::Submit { built, bytes, .. }) => (built, bytes),
            other => panic!("{other:?}"),
        };
        let (built, bytes) = submitted(reporter.attempt(c.look(&view, me_index, own(me) - 1), &votes, anchors));
        assert!(built.report.proposals.is_empty());
        assert_eq!(built.members, BTreeSet::from([me]), "its own vote alone");
        handoff::presence::verify(&view, own(me), &PresenceReport::from_canonical_bytes(&bytes).unwrap(), anchors).unwrap();
        // Lost on the way (GLOBAL still has no record): reported again.
        let retry = own(me) - 1 + PACE.resubmit_frames();
        let (_, again) = submitted(reporter.attempt(c.look(&view, me_index, retry), &votes, anchors));
        assert_eq!(reporter.schedule.submitted, 2);
        // A failed publication gives its budget and its turn back.
        publication_failed(&again);
        assert!(reporter.attempt(c.look(&view, me_index, retry + 1), &votes, anchors).is_none());
        assert_eq!((reporter.schedule.submitted, reporter.schedule.self_reported), (1, None));
        // Once GLOBAL records it, it reports itself no more.
        handoff::set_presence_credit_frame_for_thread(Some(0));
        let state = quil_execution::hypergraph_state::HypergraphState::new(global.crdt.clone());
        let recorded = retry + 2;
        handoff::presence::apply(&state, recorded, &PresenceReport::from_canonical_bytes(&bytes).unwrap(), anchors).unwrap();
        state.commit().unwrap();
        state.abort();
        global.crdt.commit_with_global_cursor(recorded, &quil_store::encoding::global_materialized_cursor_key()).unwrap();
        let view = global.view();
        let after = reporter.attempt(c.look(&view, me_index, recorded + PACE.resubmit_frames()), &votes, anchors).unwrap();
        assert!(matches!(after.outcome, Outcome::NotDesignated { .. }), "{after:?}");
        handoff::set_presence_credit_frame_for_thread(None);
        handoff::set_presence_exclusion_frame_for_thread(None);
    }

    /// A vote that does not verify neither makes its signer the submitter
    /// nor keeps the member first among the verified voters from it.
    #[test]
    fn the_submitter_is_chosen_from_votes_that_verify() {
        let _active = Active::new();
        let c = committee(4);
        let global = Global::new(&c.session);
        let view = global.view();
        let forger = c.designated(&[0, 1, 2, 3]);
        let honest: Vec<u32> = (0..4).filter(|member| *member != forger).collect();
        let me = c.designated(&honest);
        let mut seen = c.seen(5, c.anchor(), &[0, 1, 2, 3]);
        seen.votes[forger as usize].1[20] ^= 1;
        let votes = Votes::of(vec![seen]);
        let frame = c.inclusion() - 1;
        let attempt = PresenceReporter::default().attempt(c.look(&view, me as usize, frame), &votes, anchors);
        let (built, voters) = match attempt {
            Some(Attempt { outcome: Outcome::Submit { built, voters, .. }, .. }) => (built, voters),
            other => panic!("{other:?}"),
        };
        assert_eq!(voters, 3);
        assert_eq!(built.members, honest.iter().copied().collect());
        for member in (0..4).filter(|member| *member != me) {
            let attempt = PresenceReporter::default().attempt(c.look(&view, member as usize, frame), &votes, anchors);
            assert!(
                matches!(attempt, Some(Attempt {
                    outcome: Outcome::NotDesignated { designated: Some(designated), voters: 3 }, log: true, ..
                }) if designated == me),
                "member {member}: {attempt:?}",
            );
        }
    }

    /// A member that verified no vote cannot tell who submits, and says so
    /// under its own cause; once votes verify, its deferral to the
    /// submitter is a new line.
    #[test]
    fn a_member_without_verified_votes_says_so_apart_from_deferring() {
        let _active = Active::new();
        let c = committee(4);
        let global = Global::new(&c.session);
        let view = global.view();
        let member = (c.designated(&[0, 1, 2, 3]) as usize + 1) % 4;
        let frame = c.inclusion() - 1;
        let mut forged = c.seen(5, c.anchor(), &[0, 1, 2, 3]);
        for (_, signature) in &mut forged.votes {
            signature[20] ^= 1;
        }
        let mut reporter = PresenceReporter::default();
        let attempt = reporter.attempt(c.look(&view, member, frame), &Votes::of(vec![forged]), anchors).unwrap();
        assert!(matches!(attempt.outcome, Outcome::NotDesignated { designated: None, voters: 0 }) && attempt.log);
        let votes = Votes::of(vec![c.seen(6, c.anchor(), &[0, 1, 2, 3])]);
        let attempt = reporter.attempt(c.look(&view, member, frame + PACE.check_frames()), &votes, anchors).unwrap();
        assert!(matches!(attempt.outcome, Outcome::NotDesignated { designated: Some(_), voters: 4 }));
        assert!(attempt.log, "a new cause, logged too");
    }

    /// A report whose publication failed no longer counts against the
    /// epoch's budget or its members: the next due look builds it again.
    #[test]
    fn an_unpublished_report_gives_its_budget_back() {
        let _active = Active::new();
        let c = committee(4);
        let global = Global::new(&c.session);
        let view = global.view();
        let me = c.designated(&[0, 1, 2, 3]) as usize;
        let frame = c.inclusion() - 1;
        let votes = Votes::of(vec![c.seen(5, c.anchor(), &[0, 1, 2, 3])]);
        let mut reporter = PresenceReporter::default();
        let bytes = match reporter.attempt(c.look(&view, me, frame), &votes, anchors).map(|attempt| attempt.outcome) {
            Some(Outcome::Submit { bytes, .. }) => bytes,
            other => panic!("{other:?}"),
        };
        publication_failed(&bytes);
        let again = reporter.attempt(c.look(&view, me, frame + PACE.resubmit_frames()), &votes, anchors);
        assert!(
            matches!(again, Some(Attempt { outcome: Outcome::Submit { added: 4, .. }, .. })),
            "built again: {again:?}",
        );
    }

    /// A stalled session is looked at only every few committed GLOBAL
    /// frames, each vote is copied and verified once, and only the
    /// submitter reads bodies.
    #[test]
    fn a_member_looks_again_only_every_few_frames_and_verifies_each_vote_once() {
        let _active = Active::new();
        let c = committee(4);
        let global = Global::new(&c.session);
        let view = global.view();
        let designated = c.designated(&[0, 1, 2, 3]) as usize;
        let other = (designated + 1) % 4;
        let frame = c.inclusion() - 1;
        let votes = Votes::of(vec![c.seen(5, c.anchor(), &[0, 1, 2, 3])]);
        let mut reporter = PresenceReporter::default();
        let attempt = reporter.attempt(c.look(&view, other, frame), &votes, anchors).unwrap();
        assert!(matches!(attempt.outcome, Outcome::NotDesignated { designated: Some(d), voters: 4 } if d as usize == designated));
        assert!(attempt.log);
        assert_eq!((reporter.verifications(), votes.reads()), (4, (1, 4, 0)));
        // Within the spacing nothing is read or verified.
        assert!(reporter.attempt(c.look(&view, other, frame + 1), &votes, anchors).is_none());
        assert_eq!((reporter.verifications(), votes.reads()), (4, (1, 4, 0)));
        // The next look lists the votes again, but copies and verifies none
        // twice, and logs nothing new this epoch.
        let attempt = reporter.attempt(c.look(&view, other, frame + PACE.check_frames()), &votes, anchors).unwrap();
        assert!(matches!(attempt.outcome, Outcome::NotDesignated { .. }) && !attempt.log);
        assert_eq!((reporter.verifications(), votes.reads()), (4, (2, 4, 0)));
        // The submitter with nothing to report: the same spacing and checks.
        let stale = Votes::of(vec![c.seen(5, STALE, &[0, 1, 2, 3])]);
        let mut reporter = PresenceReporter::default();
        let attempt = reporter.attempt(c.look(&view, designated, frame), &stale, anchors).unwrap();
        let why = Ineligible { sealed: 1, anchored_ahead: 0, anchored_before: 1, unverified: 0 };
        assert!(matches!(attempt.outcome, Outcome::NothingEligible(found) if found == why) && attempt.log);
        assert!(reporter.attempt(c.look(&view, designated, frame + 1), &stale, anchors).is_none());
        let attempt = reporter.attempt(c.look(&view, designated, frame + PACE.check_frames()), &stale, anchors).unwrap();
        assert!(matches!(attempt.outcome, Outcome::NothingEligible(_)) && !attempt.log);
        assert_eq!((reporter.verifications(), stale.reads()), (4, (2, 4, 2)));
    }

    /// Waits this node expects (an anchor it lacks, a session its view does
    /// not hold) are told apart from a report GLOBAL would refuse; a wait is
    /// logged once per cause and epoch, a refusal every time.
    #[test]
    fn expected_waits_are_told_apart_from_refusals() {
        let _active = Active::new();
        let c = committee(4);
        let global = Global::new(&c.session);
        let view = global.view();
        let me = c.designated(&[0, 1, 2, 3]) as usize;
        let frame = c.inclusion() - 1;
        let votes = Votes::of(vec![c.seen(5, c.anchor(), &[0, 1, 2, 3])]);
        let missing = |_: u64| -> Result<Vec<u8>> { Err(QuilError::Store("no such frame".into())) };
        let mut reporter = PresenceReporter::default();
        let attempt = reporter.attempt(c.look(&view, me, frame), &votes, missing).unwrap();
        assert!(matches!(attempt.outcome, Outcome::Wait(Wait::Anchor { anchor }) if anchor == c.anchor()) && attempt.log);
        let attempt = reporter.attempt(c.look(&view, me, frame + PACE.check_frames()), &votes, missing).unwrap();
        assert!(matches!(attempt.outcome, Outcome::Wait(Wait::Anchor { .. })) && !attempt.log, "once per epoch");
        // The anchor arrives: the report goes out.
        let attempt = reporter.attempt(c.look(&view, me, frame + 2 * PACE.check_frames()), &votes, anchors).unwrap();
        assert!(matches!(attempt.outcome, Outcome::Submit { .. }));
        // An anchor output other than the one the frames were built on: the
        // check GLOBAL applies refuses the report, a defect. It is logged at
        // the first refusal of the epoch and then every fourth, with the
        // count and the first refused frame.
        let wrong = |frame: u64| anchors(frame + 1);
        let mut reporter = PresenceReporter::default();
        let mut logged = Vec::new();
        for k in 0..4 {
            let attempt = reporter.attempt(c.look(&view, me, frame + k * PACE.resubmit_frames()), &votes, wrong).unwrap();
            let Outcome::Refused { refusals, since, .. } = attempt.outcome else { panic!("{:?}", attempt.outcome) };
            assert_eq!((refusals, since), (k as u32 + 1, frame + 1));
            logged.push(attempt.log);
            if k == 0 {
                assert!(reporter.attempt(c.look(&view, me, frame + PACE.check_frames()), &votes, wrong).is_none(), "spaced");
            }
        }
        assert_eq!(logged, [true, false, false, true]);
        // A session this node's GLOBAL view does not hold.
        let d = committee(4);
        let votes = Votes::of(vec![d.seen(5, d.anchor(), &[0, 1, 2, 3])]);
        let me = d.designated(&[0, 1, 2, 3]) as usize;
        let attempt = PresenceReporter::default().attempt(d.look(&view, me, d.inclusion() - 1), &votes, anchors).unwrap();
        assert!(matches!(attempt.outcome, Outcome::Wait(Wait::UnknownSession)), "{attempt:?}");
    }

    /// A report that could land after its epoch ends is held.
    #[test]
    fn a_report_is_held_near_the_epoch_end_or_while_the_view_trails() {
        let _active = Active::new();
        let c = committee(4);
        let global = Global::new(&c.session);
        let view = global.view();
        let votes = Votes::of(vec![c.seen(5, c.anchor(), &[0, 1, 2, 3])]);
        let frame = c.inclusion() - 1;
        let next_epoch = (PACE.epoch(INCLUSION) + 1) * PACE.length;
        let mut look = c.look(&view, 0, frame);
        look.latest = Some(next_epoch);
        let attempt = PresenceReporter::default().attempt(look, &votes, anchors).unwrap();
        assert!(matches!(attempt.outcome, Outcome::Held(Hold::ViewBehind { latest }) if latest == next_epoch));
        let late = next_epoch - PACE.margin_frames();
        let mut look = c.look(&view, 0, frame);
        look.latest = Some(late);
        let attempt = PresenceReporter::default().attempt(look, &votes, anchors).unwrap();
        assert!(matches!(attempt.outcome, Outcome::Held(Hold::EpochEnd { landing }) if landing == late + 1));
        assert_eq!(votes.reads(), (0, 0, 0), "held before any vote is read");
    }

    #[test]
    fn one_voter_submits_and_the_submitter_rotates_by_epoch() {
        let session = [7; 32];
        let voters = BTreeSet::from([0, 1, 2, 3]);
        assert_eq!(designated_submitter(&session, 4, &BTreeSet::new()), None);
        let picks: BTreeSet<u32> = (0..64).filter_map(|epoch| designated_submitter(&session, epoch, &voters)).collect();
        assert!(picks.is_subset(&voters));
        assert!(picks.len() > 1, "the submitter changes across epochs");
        // A member that does not vote is never chosen; the others agree.
        for epoch in 0..16 {
            let first = designated_submitter(&session, epoch, &voters).unwrap();
            let without: BTreeSet<u32> = voters.iter().copied().filter(|voter| *voter != first).collect();
            let next = designated_submitter(&session, epoch, &without).unwrap();
            assert_ne!(next, first);
            assert_eq!(designated_submitter(&session, epoch, &voters), Some(first));
        }
    }

    #[test]
    fn nothing_is_built_before_the_presence_report_frame_or_late_in_an_epoch() {
        let mainnet = Pace { length: 720 };
        assert_eq!(mainnet.margin_frames(), 30);
        assert!(!mainnet.window_open(1_000, u64::MAX), "unset on mainnet");
        assert!(!mainnet.window_open(999, 1_000));
        assert!(mainnet.window_open(1_000, 1_000));
        // 1440 + 689 leaves 31 frames in its epoch, 1440 + 690 leaves 30.
        assert!(mainnet.window_open(1_440 + 689, 0));
        assert!(!mainnet.window_open(1_440 + 690, 0));
        assert!(!mainnet.window_open(1_440 + 719, 0));
        assert!(mainnet.window_open(2_160, 0));
        // The thread's setting, never the process environment.
        handoff::set_presence_report_frame_for_thread(Some(u64::MAX));
        assert!(!PACE.window_open(INCLUSION, handoff::presence_report_frame()), "unset");
        let active = Active::new();
        assert!(PACE.window_open(INCLUSION, handoff::presence_report_frame()));
        drop(active);
        assert!(!PACE.window_open(INCLUSION, handoff::presence_report_frame()));
    }

    #[test]
    fn a_member_reports_again_only_for_new_members_within_its_budget() {
        let (spacing, every) = (Pace { length: 720 }.resubmit_frames(), Pace { length: 720 }.check_frames());
        assert_eq!((spacing, every), (60, 3));
        let mut schedule = PresenceSchedule::default();
        schedule.observe([1; 32], 10);
        assert!(schedule.due(7_205, spacing));
        let first = BTreeSet::from([0, 1]);
        assert_eq!(schedule.adds(&first), 2);
        schedule.submitted(7_205, &first);
        assert!(!schedule.due(7_206, spacing), "spaced apart");
        assert!(schedule.due(7_205 + 60, spacing));
        assert_eq!(schedule.adds(&first), 0, "nothing new");
        assert_eq!(schedule.adds(&BTreeSet::from([0, 1, 2])), 1);
        schedule.submitted(7_265, &BTreeSet::from([0, 1, 2]));
        schedule.submitted(7_325, &BTreeSet::from([3]));
        assert!(!schedule.due(7_500, spacing), "at most three reports per session and epoch");
        // Another epoch, or another session, starts over.
        schedule.observe([1; 32], 11);
        assert!(schedule.due(7_920, spacing));
        assert_eq!(schedule.adds(&first), 2);
        schedule.observe([2; 32], 11);
        // A report that adds nobody, or that the local check refused, also
        // waits out the spacing.
        schedule.idle(7_921);
        assert!(!schedule.due(7_922, spacing));
        assert!(schedule.due(7_921 + 60, spacing));
        assert_eq!(schedule.refused(7_990), (1, 7_990));
        assert!(!schedule.due(7_991, spacing));
        assert!(schedule.due(7_990 + 60, spacing));
        // Looks are spaced, and each cause is noted once per epoch.
        assert!(schedule.look(7_920, every));
        assert!(!schedule.look(7_920 + every - 1, every));
        assert!(schedule.look(7_920 + every, every));
        assert!(schedule.note("not designated"));
        assert!(!schedule.note("not designated"));
        assert!(schedule.note("nothing eligible"));
        schedule.observe([2; 32], 12);
        assert!(schedule.note("not designated"));
        assert!(schedule.look(7_920 + every, every));
    }

    /// Sessions' first reports of an epoch are spread over its first
    /// quarter, each session at its own frame, the same every epoch; a
    /// member does not even look before it.
    #[test]
    fn a_session_reports_from_its_own_frame_of_the_first_quarter_epoch() {
        let mainnet = Pace { length: 720 };
        let offsets: BTreeSet<u64> = (0..64u8).map(|i| mainnet.first_frame(&[i; 32], 10) - 7_200).collect();
        assert!(offsets.iter().all(|offset| *offset < 180), "{offsets:?}");
        assert!(offsets.len() > 32, "spread: {offsets:?}");
        assert_eq!(mainnet.first_frame(&[1; 32], 11) - mainnet.first_frame(&[1; 32], 10), 720);
        let _active = Active::new();
        // A session whose first frame is not its epoch's first.
        let c = loop {
            let c = committee(4);
            if PACE.first_frame(&c.id, PACE.epoch(INCLUSION)) > 7_201 {
                break c;
            }
        };
        let global = Global::new(&c.session);
        let view = global.view();
        let first = PACE.first_frame(&c.id, PACE.epoch(INCLUSION));
        let votes = Votes::of(vec![c.seen(5, first - 1, &[0, 1, 2, 3])]);
        let mut reporter = PresenceReporter::default();
        assert!(reporter.attempt(c.look(&view, 0, first - 2), &votes, anchors).is_none());
        assert_eq!(votes.reads(), (0, 0, 0), "nothing read before its first frame");
        assert!(reporter.attempt(c.look(&view, 0, first - 1), &votes, anchors).is_some());
        assert_eq!(votes.reads().0, 1);
    }
}
