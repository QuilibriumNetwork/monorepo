//! Silent-prover early successor: GLOBAL fences an app-shard session that
//! stopped producing because members went silent on every shard they
//! serve, and seats its successor without them.
//!
//! A session's quorum is fixed for its life, so members that vanish (one
//! operator's site going down, say) can leave it below quorum until the
//! normal path fences it, two epochs after a membership request that the
//! next epoch boundary may not even make. Only GLOBAL authorizes sessions,
//! so a successor it seats is a new session with its own namespace: no vote
//! of the old one counts in it, and GLOBAL refuses the old session's frames
//! past the fence. What this adds is the decision, from committed state
//! every GLOBAL node reads alike.
//!
//! At a session pass ([`super::schedule::SESSION_PASS_FRAMES`]), a session
//! is stalled when its executed tip has not advanced for
//! [`Settings::window`] GLOBAL frames (K; [`stalled`]). It is evaluated at
//! the first pass after that and once per K frames while it stays stalled
//! ([`evaluate`]). A member is silent when no allocation of its, on any
//! shard, signed an app frame GLOBAL included in the window (its
//! `LastSignedFrameNumber`, which confirms do not advance), while at least
//! [`Settings::evidence`] (M) of its other shards, where it sits in the
//! head session, had a frame included in that window. A member without
//! that evidence (one allocation, or its other shards stalled too) is
//! never silent: no evidence never excludes anyone. GLOBAL acts only if
//! the members not silent are at most a quorum, so that silence explains
//! the stall (no margin is left), and then removes at most ⌊(n−1)/3⌋ of
//! the silent ones, the longest silent first, keeping at least
//! [`MIN_COMMITTEE`] members, and only if the session's members that
//! signed an included frame in the window reach the successor's quorum. A
//! member without evidence either way is not counted on: a successor that
//! needed it could stall at once, with no evidence to exclude it. The
//! successor is a new session too, so a further step waits until it has
//! itself stalled K frames.
//!
//! An excluded member keeps its allocations; it is only not seated on that
//! shard ([`seated`]). Its exclusion ends once any allocation of its signs
//! an included frame after the fence: the next successor of the shard,
//! normally the membership successor of the next epoch boundary, seats it
//! again through a seal. Silent seats earn nothing because they sign
//! nothing; there is no other penalty.
//!
//! Everything here is GLOBAL consensus, from [`first_frame`]: the later of
//! [`MAINNET_SILENT_FENCE_FRAME`] and one epoch after
//! [`quil_types::consensus::signed_frame_activation_frame`], from which
//! signatures and tip-advance frames are recorded.

use quil_cw_consensus::handoff::{put_bytes, Cursor, Session};
use quil_types::error::{QuilError, Result};
use std::collections::HashMap;

use super::exclusion::{quorum, MIN_COMMITTEE};
use super::{head, read, session_tip, session_tip_frame, status, write, Records, Status};
use crate::hypergraph_state::HypergraphState;
use crate::prover_registry::CommittedProverScan;

/// GLOBAL frames a session's executed tip must stand still before GLOBAL
/// judges its members' silence (K): 90 frames, about 15 minutes. On the
/// 2026-11-04 loss of one site's provers (GLOBAL frame 1,002,306) the
/// stalled shards would have had successors by about 12:17 UTC instead of
/// the timeout fence near 17:53 UTC. Long enough that a live member signs
/// an included certificate on its other shards, which certify a frame
/// every few GLOBAL frames.
pub const WINDOW_FRAMES: u64 = 90;

/// Other shards with a frame included in the window, on which a member
/// sits in the head session, needed before its silence counts (M): 3.
pub const EVIDENCE_SHARDS: usize = 3;

/// From this mainnet GLOBAL frame (and not before one epoch after the
/// signed-frame activation frame, [`first_frame`]) GLOBAL fences stalled
/// sessions without their silent members. Consensus-affecting for GLOBAL:
/// every archive and GLOBAL prover must run a build with it before the
/// frame; an older build seats no such successor and commits another
/// GLOBAL state. App provers need nothing new: they date an early fence by
/// the frame GLOBAL records for it (`schedule::fence_frame`), as for a
/// presence exclusion. Proposed with the seal successor eligibility frame
/// (`MAINNET_SEAL_SUCCESSOR_ELIGIBILITY_FRAME`) at or before it, so a seal
/// that closes a stalled session late seats current eligibility, which
/// leaves silent members out, rather than the committee its request fixed.
/// Mainnet: 1,072,800, the first frame of epoch 1490, which GLOBAL cannot
/// reach before 2026-11-13 02:00 UTC even at ten seconds a frame; set once
/// every archive and 99.9% of the workers measured ran a release carrying
/// the fence (2026-11-10 11:04 UTC);
/// `QUIL_SILENT_FENCE_FRAME` elsewhere, never by default, with
/// `QUIL_SILENT_WINDOW_FRAMES` (K) and `QUIL_SILENT_EVIDENCE_SHARDS` (M).
pub const MAINNET_SILENT_FENCE_FRAME: Option<u64> = Some(1_072_800);

/// Kind of the handoff record of a member's silent exclusion on a filter.
const SILENT: &[u8] = b"silent-exclusion";

/// Kind of the handoff record naming a session a silent fence authorized,
/// for its end line.
const SILENT_SUCCESSOR: &[u8] = b"silent-successor";

/// Version of a silent exclusion record's encoding.
const RECORD_VERSION: u8 = 1;

/// Members named in one log line at most.
const LOGGED_MEMBERS: usize = 16;

/// The silent-prover fence's schedule and parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// The configured first frame ([`MAINNET_SILENT_FENCE_FRAME`]).
    pub frame: u64,
    /// K: GLOBAL frames of stall, and of silence, before GLOBAL acts.
    pub window: u64,
    /// M: other producing shards a member's silence needs as evidence.
    pub evidence: usize,
}

static SETTINGS: std::sync::OnceLock<Settings> = std::sync::OnceLock::new();

thread_local! {
    static SETTINGS_OVERRIDE: std::cell::Cell<Option<Settings>> = const { std::cell::Cell::new(None) };
}

fn settings_for(
    network: u8,
    frame: Option<&str>,
    window: Option<&str>,
    evidence: Option<&str>,
) -> Settings {
    if network == 0 {
        return Settings {
            frame: MAINNET_SILENT_FENCE_FRAME.unwrap_or(u64::MAX),
            window: WINDOW_FRAMES,
            evidence: EVIDENCE_SHARDS,
        };
    }
    Settings {
        frame: frame.and_then(|v| v.parse().ok()).unwrap_or(u64::MAX),
        window: window
            .and_then(|v| v.parse().ok())
            .filter(|&k: &u64| k > 0)
            .unwrap_or(WINDOW_FRAMES),
        // At least one: without evidence a member is never silent.
        evidence: evidence
            .and_then(|v| v.parse().ok())
            .filter(|&m: &usize| m > 0)
            .unwrap_or(EVIDENCE_SHARDS),
    }
}

/// Fix this process's silent-prover fence settings from its network, and
/// return them. Called at startup before any frame is processed; the first
/// call decides.
pub fn init_silent_fence(network: u8) -> Settings {
    *SETTINGS.get_or_init(|| {
        let var = |name: &str| std::env::var(name).ok();
        settings_for(
            network,
            var("QUIL_SILENT_FENCE_FRAME").as_deref(),
            var("QUIL_SILENT_WINDOW_FRAMES").as_deref(),
            var("QUIL_SILENT_EVIDENCE_SHARDS").as_deref(),
        )
    })
}

/// The settings fixed by [`init_silent_fence`]; the mainnet ones in a
/// process that never called it.
pub fn settings() -> Settings {
    if let Some(settings) = SETTINGS_OVERRIDE.with(|cell| cell.get()) {
        return settings;
    }
    SETTINGS
        .get()
        .copied()
        .unwrap_or_else(|| settings_for(0, None, None, None))
}

/// Set the settings for the calling thread only (tests); `None` restores
/// the process's.
pub fn set_settings_for_thread(settings: Option<Settings>) {
    SETTINGS_OVERRIDE.with(|cell| cell.set(settings));
}

/// The first GLOBAL frame the evaluator runs at: the configured frame, but
/// not before one epoch after the signed-frame activation frame, so every
/// member has had a full epoch of recorded signatures and every session a
/// recorded tip-advance frame. `u64::MAX` while either is unscheduled.
pub fn first_frame() -> u64 {
    let signed = quil_types::consensus::signed_frame_activation_frame();
    if signed == u64::MAX {
        return u64::MAX;
    }
    settings()
        .frame
        .max(signed.saturating_add(quil_types::consensus::epoch_length_frames()))
}

/// Whether the evaluator runs at GLOBAL frame `frame` ([`first_frame`]).
pub fn evaluates(frame: u64) -> bool {
    frame >= first_frame()
}

/// A member's silent exclusion from one filter's sessions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exclusion {
    /// The GLOBAL frame of the fence that excluded it.
    pub excluded_at: u64,
    /// The GLOBAL frame the membership pass found it signing again and
    /// logged its return; zero while open.
    pub ended_at: u64,
}

impl Exclusion {
    /// Whether the member is still left out, given the latest GLOBAL frame
    /// any allocation of its signed an included app frame at.
    pub fn in_effect(&self, last_signed: u64) -> bool {
        self.ended_at == 0 && last_signed <= self.excluded_at
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = vec![RECORD_VERSION];
        out.extend_from_slice(&self.excluded_at.to_be_bytes());
        out.extend_from_slice(&self.ended_at.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let corrupt = || QuilError::Store("corrupt silent exclusion record".into());
        let mut c = Cursor::new(bytes).map_err(|_| corrupt())?;
        if c.u8().map_err(|_| corrupt())? != RECORD_VERSION {
            return Err(corrupt());
        }
        let excluded_at = c.u64().map_err(|_| corrupt())?;
        let ended_at = c.u64().map_err(|_| corrupt())?;
        c.finish().map_err(|_| corrupt())?;
        Ok(Self {
            excluded_at,
            ended_at,
        })
    }
}

fn record_key(filter: &[u8], member: &[u8]) -> Result<Vec<u8>> {
    let mut key = Vec::new();
    put_bytes(&mut key, filter)?;
    key.extend_from_slice(member);
    Ok(key)
}

/// The latest silent exclusion of `member` from `filter`'s sessions, in
/// effect or not.
pub fn exclusion(state: &impl Records, filter: &[u8], member: &[u8]) -> Result<Option<Exclusion>> {
    read(state, SILENT, &record_key(filter, member)?)?
        .map(|bytes| Exclusion::decode(&bytes))
        .transpose()
}

fn set_exclusion(
    state: &HypergraphState,
    frame: u64,
    filter: &[u8],
    member: &[u8],
    value: &Exclusion,
) -> Result<()> {
    write(
        state,
        frame,
        SILENT,
        &record_key(filter, member)?,
        &value.encode(),
    )
}

/// The latest GLOBAL frame any allocation of each prover (by Falcon key)
/// signed an included app frame at. One pass over the scan, built only
/// once a call meets an exclusion record.
fn last_signed_by_key(scan: &CommittedProverScan) -> HashMap<&[u8], u64> {
    let mut last: HashMap<&[u8], u64> = HashMap::new();
    for (address, alloc) in &scan.allocations {
        if let Some(key) = scan.public_key(address) {
            let entry = last.entry(key).or_insert(0);
            *entry = (*entry).max(alloc.last_signed_frame_number);
        }
    }
    last
}

/// `desired`, the provers to seat on `filter` at GLOBAL frame `frame`, less
/// the members whose silent exclusion is in effect ([`Exclusion::in_effect`]).
/// Unchanged before [`first_frame`], and unchanged if the exclusions would
/// leave fewer than [`MIN_COMMITTEE`] members.
pub fn seated(
    state: &impl Records,
    frame: u64,
    filter: &[u8],
    desired: Vec<Vec<u8>>,
    scan: &CommittedProverScan,
) -> Result<Vec<Vec<u8>>> {
    if !evaluates(frame) {
        return Ok(desired);
    }
    let mut kept = Vec::with_capacity(desired.len());
    let mut last = None;
    for member in &desired {
        let withheld = match exclusion(state, filter, member)? {
            Some(excluded) => {
                let last = last.get_or_insert_with(|| last_signed_by_key(scan));
                excluded.in_effect(last.get(member.as_slice()).copied().unwrap_or(0))
            }
            None => false,
        };
        if !withheld {
            kept.push(member.clone());
        }
    }
    if kept.len() == desired.len() || kept.len() < MIN_COMMITTEE {
        return Ok(desired);
    }
    Ok(kept)
}

/// Close the silent exclusions of `members` (the committee the membership
/// pass seats on `filter` at `frame`) that signed again since their fence,
/// logging each return once. Returns how many it closed.
pub fn end_returned(
    state: &HypergraphState,
    frame: u64,
    filter: &[u8],
    members: &[Vec<u8>],
    scan: &CommittedProverScan,
) -> Result<usize> {
    if !evaluates(frame) {
        return Ok(0);
    }
    let mut ended = 0;
    let mut last = None;
    for member in members {
        let Some(excluded) = exclusion(state, filter, member)? else {
            continue;
        };
        let signed = last
            .get_or_insert_with(|| last_signed_by_key(scan))
            .get(member.as_slice())
            .copied()
            .unwrap_or(0);
        if excluded.ended_at != 0 || excluded.in_effect(signed) {
            continue;
        }
        set_exclusion(
            state,
            frame,
            filter,
            member,
            &Exclusion {
                ended_at: frame,
                ..excluded
            },
        )?;
        ended += 1;
        tracing::info!(
            frame,
            filter = hex::encode(filter),
            prover = describe(member),
            excluded_at = excluded.excluded_at,
            signed_at = signed,
            "committee silence: an excluded prover signed again; its shard's next session seats it"
        );
    }
    Ok(ended)
}

/// A prover address for logs: the Poseidon of the member's key.
fn describe(member: &[u8]) -> String {
    crate::global_intrinsic::materialize::prover_address_from_pubkey(member)
        .map(hex::encode)
        .unwrap_or_default()
}

/// A head session whose executed tip has stood still for at least K GLOBAL
/// frames, due for evaluation at this pass ([`stalled`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stalled {
    pub filter: Vec<u8>,
    pub session: Session,
    pub id: [u8; 32],
    /// The GLOBAL frame of its last tip advance, or of its creation.
    pub tip_frame: u64,
}

/// The head sessions among `filters` due for evaluation at the session pass
/// of GLOBAL frame `frame`: Active, or closing for a membership change, not
/// reserved by a pending split or merge, whose tip last advanced (or which
/// started) K or more frames before `frame`, at the first pass after that
/// and once per K frames after. Reads only a few records per shard, so the
/// prover scan is built only when this is not empty. A session without a
/// recorded tip-advance frame (untouched since before the signed-frame
/// activation frame) is not evaluated; it is logged once per epoch.
pub fn stalled(state: &impl Records, frame: u64, filters: &[Vec<u8>]) -> Result<Vec<Stalled>> {
    let mut out = Vec::new();
    if !evaluates(frame) {
        return Ok(out);
    }
    let window = settings().window;
    let pass = super::schedule::SESSION_PASS_FRAMES;
    for filter in filters {
        let Some(session) = head(state, filter)? else {
            continue;
        };
        let id = session.id()?;
        let Some(tip_frame) = session_tip_frame(state, &id)? else {
            if super::schedule::first_pass_of_epoch(frame) && status(state, &id)? == Status::Active
            {
                tracing::info!(
                    frame,
                    filter = hex::encode(filter),
                    generation = session.generation,
                    "committee silence: session has no recorded tip-advance frame; its stall is \
                     not judged until its tip advances (the timeout fence still applies)"
                );
            }
            continue;
        };
        let Some(age) = frame.checked_sub(tip_frame) else {
            continue;
        };
        if age < window || (age - window) % window >= pass {
            continue;
        }
        match status(state, &id)? {
            Status::Closed(_) => continue,
            Status::Active => {
                if super::schedule::reserved(state, filter)? {
                    note(
                        frame,
                        filter,
                        &session,
                        age,
                        "its shard is reserved by a pending split or merge",
                    );
                    continue;
                }
            }
            Status::Sealing(request_id) => {
                let pending = super::request(state, &request_id)?.ok_or_else(|| {
                    QuilError::Store("closing session's request is absent".into())
                })?;
                if !super::schedule::membership_request(&pending, filter) {
                    note(
                        frame,
                        filter,
                        &session,
                        age,
                        "it is closing for a split or merge",
                    );
                    continue;
                }
            }
        }
        out.push(Stalled {
            filter: filter.clone(),
            session,
            id,
            tip_frame,
        });
    }
    Ok(out)
}

fn note(frame: u64, filter: &[u8], session: &Session, stalled_frames: u64, reason: &'static str) {
    tracing::info!(
        frame,
        filter = hex::encode(filter),
        generation = session.generation,
        stalled_frames,
        reason,
        "committee silence: stalled session left to its split, merge or timeout"
    );
}

/// A stalled session [`evaluate`] fences without its silent members.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub filter: Vec<u8>,
    /// The stalled session's ID.
    pub session: [u8; 32],
    /// Its successor's committee: the shard's seated provers less the
    /// removed, sorted.
    pub committee: Vec<Vec<u8>>,
    /// The removed members, longest silent first, with the last frame each
    /// signed at.
    pub excluded: Vec<(Vec<u8>, u64)>,
}

/// Each member's signing record, from one pass over the scan.
struct Signing {
    last: u64,
    filters: Vec<Vec<u8>>,
}

fn signing_index(scan: &CommittedProverScan) -> HashMap<&[u8], Signing> {
    let mut index: HashMap<&[u8], Signing> = HashMap::new();
    for (address, alloc) in &scan.allocations {
        let Some(key) = scan.public_key(address) else {
            continue;
        };
        let entry = index.entry(key).or_insert(Signing {
            last: 0,
            filters: Vec::new(),
        });
        entry.last = entry.last.max(alloc.last_signed_frame_number);
        if !alloc.confirmation_filter.is_empty() {
            entry.filters.push(alloc.confirmation_filter.clone());
        }
    }
    for signing in index.values_mut() {
        signing.filters.sort();
        signing.filters.dedup();
    }
    index
}

/// The members of `filter`'s head session if GLOBAL included a frame of it
/// after `since`; `None` otherwise. Cached per filter for one pass.
fn producing<'c>(
    state: &impl Records,
    since: u64,
    filter: &[u8],
    cache: &'c mut HashMap<Vec<u8>, Option<Vec<Vec<u8>>>>,
) -> Result<&'c Option<Vec<Vec<u8>>>> {
    if !cache.contains_key(filter) {
        let members = match head(state, filter)? {
            Some(session) => {
                let id = session.id()?;
                let advanced = session_tip(state, &id)?.is_some()
                    && session_tip_frame(state, &id)?.is_some_and(|at| at > since);
                advanced.then_some(session.members)
            }
            None => None,
        };
        cache.insert(filter.to_vec(), members);
    }
    Ok(&cache[filter])
}

/// Callback giving a filter's provers to seat.
type Desired<'a> = dyn FnMut(&[u8]) -> Result<Vec<Vec<u8>>> + 'a;

/// Decide, for each of `stalled` ([`stalled`]), whether its silent members
/// explain its stall and, once they are removed, its members that signed in
/// the window reach the successor's quorum, and return those sessions with
/// their successors' committees. Writes nothing: [`fence`] fences each and
/// records its exclusions together, or neither.
/// `desired` gives a filter's provers to seat (eligibility less exclusions,
/// as the membership pass seats them). Every evaluation that acts is logged
/// with its fence; one that does not is logged with its reason.
pub fn evaluate(
    state: &impl Records,
    frame: u64,
    stalled: &[Stalled],
    scan: &CommittedProverScan,
    desired: &mut Desired<'_>,
) -> Result<Vec<Decision>> {
    let mut decisions = Vec::new();
    if stalled.is_empty() {
        return Ok(decisions);
    }
    let Settings {
        window, evidence, ..
    } = settings();
    let since = frame.saturating_sub(window);
    let index = signing_index(scan);
    let mut cache = HashMap::new();
    for candidate in stalled {
        let session = &candidate.session;
        let n = session.members.len();
        let q = quorum(n);
        // Silent: no signature anywhere in the window, while M other shards
        // it sits on produced in it.
        let mut silent: Vec<(Vec<u8>, u64)> = Vec::new();
        let mut unproven = 0usize;
        for member in &session.members {
            let Some(signing) = index.get(member.as_slice()) else {
                unproven += 1;
                continue;
            };
            if signing.last > since {
                continue;
            }
            let mut shards = 0usize;
            for other in &signing.filters {
                if *other == candidate.filter {
                    continue;
                }
                if producing(state, since, other, &mut cache)?
                    .as_ref()
                    .is_some_and(|members| members.binary_search(member).is_ok())
                {
                    shards += 1;
                }
            }
            if shards >= evidence {
                silent.push((member.clone(), signing.last));
            } else {
                unproven += 1;
            }
        }
        // Longest silent first, ties by key.
        silent.sort_by(|a, b| (a.1, &a.0).cmp(&(b.1, &b.0)));
        let present = n - silent.len();
        let skip = |reason: &'static str, committee: usize, kept: usize| {
            let committee_quorum = if committee == 0 { 0 } else { quorum(committee) };
            tracing::warn!(
                frame,
                filter = hex::encode(&candidate.filter),
                generation = session.generation,
                stalled_since = candidate.tip_frame,
                members = n,
                quorum = q,
                silent = silent.len(),
                unproven,
                present,
                committee,
                committee_quorum,
                kept_signed = kept,
                window,
                evidence,
                reason,
                "committee silence: stalled session not fenced early; it waits for its tip to \
                 advance or for its timeout fence"
            );
        };
        // With more than a quorum not silent, silence does not explain the
        // stall (GLOBAL refusing headers, a version split): a fence would
        // only discard frames.
        if present > q {
            skip(
                "the stall is not explained by silent members: the others exceed its quorum",
                0,
                0,
            );
            continue;
        }
        let cap = n.saturating_sub(1) / 3;
        let removed: Vec<(Vec<u8>, u64)> = silent.iter().take(cap).cloned().collect();
        if removed.is_empty() {
            skip("no member may be removed", 0, 0);
            continue;
        }
        let eligible = desired(candidate.filter.as_slice())?;
        if eligible.is_empty() {
            skip("no prover is eligible", 0, 0);
            continue;
        }
        let gone = |member: &[u8]| removed.iter().any(|(key, _)| key.as_slice() == member);
        let committee: Vec<Vec<u8>> = eligible
            .into_iter()
            .filter(|member| !gone(member.as_slice()))
            .collect();
        // Kept in the successor: its members that were members here and
        // signed an included frame in the window. A member shown neither
        // silent nor signing (unproven) is not counted, nor are eligible
        // provers new to the shard: both are seated, but a successor that
        // needed them to reach quorum could stall at once.
        let kept = committee
            .iter()
            .filter(|member| {
                session.members.binary_search(*member).is_ok()
                    && index
                        .get(member.as_slice())
                        .is_some_and(|signing| signing.last > since)
            })
            .count();
        if committee.len() < MIN_COMMITTEE {
            skip(
                "the committee without its silent members would fall below the consensus minimum",
                committee.len(),
                kept,
            );
            continue;
        }
        if kept < quorum(committee.len()) {
            skip(
                "its members that signed in the window would not reach quorum of the committee \
                 without its silent members; unproven members are not counted",
                committee.len(),
                kept,
            );
            continue;
        }
        tracing::info!(
            frame,
            filter = hex::encode(&candidate.filter),
            generation = session.generation,
            stalled_since = candidate.tip_frame,
            members = n,
            quorum = q,
            silent = silent.len(),
            unproven,
            removed = removed.len(),
            cap,
            committee = committee.len(),
            committee_quorum = quorum(committee.len()),
            kept_signed = kept,
            window_from = since + 1,
            window_to = frame,
            evidence,
            "committee silence: stalled session's silent members explain its stall; fencing it \
             early without them"
        );
        decisions.push(Decision {
            filter: candidate.filter.clone(),
            session: candidate.id,
            committee,
            excluded: removed,
        });
    }
    Ok(decisions)
}

/// Fence each of `decisions` early at its executed tip, authorize its
/// successor with the decision's committee, and only then record the
/// exclusions ([`super::schedule::fence_early`]). A decision refused by a
/// rule (an `InvalidArgument` error) is undone whole and logged, and the
/// others stand; any other error (a store failure) fails the whole frame,
/// on every node alike. Returns how many sessions were fenced.
pub fn fence(state: &HypergraphState, frame: u64, decisions: &[Decision]) -> Result<usize> {
    let mut fenced = 0;
    for decision in decisions {
        let checkpoint = state.changeset_len();
        match fence_one(state, frame, decision) {
            Ok(true) => fenced += 1,
            Ok(false) => {}
            Err(error) if matches!(error, QuilError::InvalidArgument(_)) => {
                state.rollback_to(checkpoint);
                tracing::error!(frame, filter = hex::encode(&decision.filter), %error,
                    "committee silence: early fence of a stalled session failed; it waits for its timeout");
            }
            Err(error) => return Err(error),
        }
    }
    Ok(fenced)
}

fn fence_one(state: &HypergraphState, frame: u64, decision: &Decision) -> Result<bool> {
    let filter = &decision.filter;
    let fenced = match super::schedule::fence_early(
        state,
        frame,
        filter,
        &decision.session,
        &decision.committee,
    )? {
        super::schedule::EarlyFence::Fenced(fenced) => fenced,
        super::schedule::EarlyFence::Reserved(session) => {
            note(
                frame,
                filter,
                &session,
                0,
                "its shard is reserved by a pending split or merge",
            );
            return Ok(false);
        }
        super::schedule::EarlyFence::NotApplicable => return Ok(false),
    };
    for (member, _) in &decision.excluded {
        set_exclusion(
            state,
            frame,
            filter,
            member,
            &Exclusion {
                excluded_at: frame,
                ended_at: 0,
            },
        )?;
    }
    let successor = head(state, filter)?
        .ok_or_else(|| QuilError::Store("early fence left no head session".into()))?;
    let mut marker = frame.to_be_bytes().to_vec();
    marker.extend_from_slice(&(decision.excluded.len() as u32).to_be_bytes());
    write(state, frame, SILENT_SUCCESSOR, &successor.id()?, &marker)?;
    let provers: Vec<String> = decision
        .excluded
        .iter()
        .take(LOGGED_MEMBERS)
        .map(|(member, signed)| format!("{} (last signed at {signed})", describe(member)))
        .collect();
    tracing::warn!(
        frame,
        filter = hex::encode(filter),
        generation = fenced.session.generation,
        members = fenced.session.members.len(),
        fenced_at = fenced.checkpoint.frame,
        request = hex::encode(fenced.request),
        requested_at = fenced.requested_at,
        successor_generation = successor.generation,
        committee = decision.committee.len(),
        committee_quorum = quorum(decision.committee.len()),
        excluded = decision.excluded.len(),
        provers = ?provers,
        "committee silence: stalled session fenced early at its executed tip; its successor \
         seats its members less the silent ones, who are seated again once they sign anywhere",
    );
    tracing::info!(
        frame,
        request = hex::encode(fenced.request),
        "committee handoff: successors authorized from fenced sources"
    );
    Ok(true)
}

/// Log, once, the first executed frame of a session a silent fence
/// authorized: the end of the stall it fenced. Called on a session's first
/// tip advance; reads one record, writes nothing.
pub(super) fn note_first_frame(
    state: &impl Records,
    frame: u64,
    id: &[u8; 32],
    data_frame: u64,
) -> Result<()> {
    if !evaluates(frame) {
        return Ok(());
    }
    let Some(marker) = read(state, SILENT_SUCCESSOR, id)? else {
        return Ok(());
    };
    let fenced_at = marker
        .get(..8)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map(u64::from_be_bytes)
        .unwrap_or(0);
    let excluded = marker
        .get(8..12)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_be_bytes)
        .unwrap_or(0);
    let session = super::session(state, id)?;
    tracing::info!(
        frame,
        filter = session.as_ref().map(|s| hex::encode(&s.filter)).unwrap_or_default(),
        generation = session.as_ref().map_or(0, |s| s.generation),
        members = session.as_ref().map_or(0, |s| s.members.len()),
        data_frame,
        fenced_at,
        frames_since_fence = frame.saturating_sub(fenced_at),
        excluded,
        "committee silence: successor of a silent-prover fence produced its first frame; the stall has ended"
    );
    Ok(())
}
