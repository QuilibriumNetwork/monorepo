//! Presence exclusion: members of a stalled app-shard session that GLOBAL
//! recorded no vote of are left out of its successor for a while.
//!
//! A session whose members do not vote cannot reach quorum, and its
//! successor seats the same eligible provers again: a re-confirm keeps an
//! allocation eligible whether or not its worker votes. Presence records
//! show who voted ([`super::presence::present`]) or at least followed the
//! session with a nullify ([`super::presence::protected`]): either counts
//! as present here. A stalled session's members often only nullify, since
//! no proposal they accept reaches them; those who send nothing at all are
//! the absent. At the first maintenance
//! pass of an epoch ([`evaluate`]), a session that stalled through the
//! previous epoch, below its quorum, and whose present members would reach
//! quorum of its committee without the members it holds no vote of, has
//! those members excluded and is fenced early
//! ([`super::schedule::fence_absent`]): its successor seats the eligible
//! provers less the excluded ones ([`seated`]). Otherwise nothing changes:
//! a missing report never excludes anyone, and a committee is never cut
//! below [`MIN_COMMITTEE`] members.
//!
//! An exclusion lasts 2^(s−1) epochs for a member's s-th strike in a row,
//! at most [`MAX_EXCLUSION_EPOCHS`]; a strike more than
//! [`RELAPSE_EPOCHS`] after the last exclusion ended starts again at one.
//! The way back: an excluded member signs a recent GLOBAL frame's beacon
//! for the filter ([`PresenceClaim`]), which ends its exclusion at the next
//! epoch boundary; its strikes stay, so a relapse doubles the next one. No
//! node produces claims: an operator submits one by hand, and otherwise the
//! exclusion simply lapses.
//!
//! Only a majority of a session's members found present can exclude the
//! rest: one reporter carries the committee's votes, and a member it left
//! out reports itself late in the epoch.
//!
//! An excluded member keeps its allocation, so coverage, other provers'
//! planning and its own lifecycle are unchanged; it is only not seated.
//! Other provers' planners therefore still count it on its shard: that
//! shard looks covered by its allocations while its successor seats the
//! present members, who reach quorum without it. Planners are left alone on
//! purpose while most committees lack quorum: changing what they see would
//! move joins between shards. Eviction, when enabled, can remove an
//! allocation that stays absent.
//! Everything here is GLOBAL consensus, from
//! [`super::presence_exclusion_frame`].

use quil_cw_consensus::handoff::{put_bytes, Cursor, Session, MAX_FILTER_BYTES};
use quil_types::error::{QuilError, Result};

use super::{
    head, presence, read, session_tip_frame, status, write, Records, Status, TYPE_PRESENCE_REPORT,
};
use crate::hypergraph_state::HypergraphState;

/// The smallest committee an exclusion may leave: the consensus minimum.
pub const MIN_COMMITTEE: usize = quil_types::consensus::MIN_SHARD_CONSENSUS_PROVERS as usize;

/// The longest exclusion, in epochs.
pub const MAX_EXCLUSION_EPOCHS: u64 = 16;

/// Epochs after an exclusion ends within which a new strike counts as a
/// relapse and doubles the next exclusion.
pub const RELAPSE_EPOCHS: u64 = 16;

/// Kind of the handoff record of a member's exclusion on a filter.
const EXCLUSION: &[u8] = b"exclusion";

/// Version of an exclusion record's encoding.
const RECORD_VERSION: u8 = 1;

/// Version byte of a [`PresenceClaim`] after the shared type prefix; a
/// presence report carries version 1.
pub const CLAIM_VERSION: u8 = 2;

/// FN-DSA domain of a presence claim's signature, apart from every
/// consensus vote.
pub const CLAIM_DOMAIN: &[u8] = b"quil/app/presence/claim/v1";

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("presence exclusion: {message}"))
}

/// Simplex quorum of a committee of `members`: ⌊2n/3⌋ + 1, as
/// `Set::quorum::<N3f1>()` counts it.
pub fn quorum(members: usize) -> usize {
    members * 2 / 3 + 1
}

/// Whether the epoch's exclusion pass runs at GLOBAL frame `frame`: its
/// first maintenance pass, from [`super::presence_exclusion_frame`].
pub fn evaluates(frame: u64) -> bool {
    frame >= super::presence_exclusion_frame() && super::schedule::first_pass_of_epoch(frame)
}

/// A member's exclusion from the sessions of one filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exclusion {
    /// Consecutive strikes, the latest included.
    pub strikes: u32,
    /// The epoch of the latest strike.
    pub from: u64,
    /// The first epoch the member is seated again.
    pub until: u64,
}

impl Exclusion {
    /// Whether the member is excluded in `epoch`.
    pub fn covers(&self, epoch: u64) -> bool {
        self.from <= epoch && epoch < self.until
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = vec![RECORD_VERSION];
        out.extend_from_slice(&self.strikes.to_be_bytes());
        out.extend_from_slice(&self.from.to_be_bytes());
        out.extend_from_slice(&self.until.to_be_bytes());
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let corrupt = || QuilError::Store("corrupt presence exclusion record".into());
        let mut c = Cursor::new(bytes).map_err(|_| corrupt())?;
        if c.u8().map_err(|_| corrupt())? != RECORD_VERSION {
            return Err(corrupt());
        }
        let strikes = c.u32().map_err(|_| corrupt())?;
        let from = c.u64().map_err(|_| corrupt())?;
        let until = c.u64().map_err(|_| corrupt())?;
        c.finish().map_err(|_| corrupt())?;
        if strikes == 0 || until <= from {
            return Err(corrupt());
        }
        Ok(Self {
            strikes,
            from,
            until,
        })
    }
}

/// Epochs the `strikes`-th consecutive strike excludes a member for: 1, 2,
/// 4, 8, then [`MAX_EXCLUSION_EPOCHS`].
pub fn exclusion_epochs(strikes: u32) -> u64 {
    (1u64 << strikes.saturating_sub(1).min(4)).min(MAX_EXCLUSION_EPOCHS)
}

/// The exclusion a strike in `epoch` records, after `previous`: the next of
/// a row while `epoch` falls within [`RELAPSE_EPOCHS`] of the previous
/// exclusion's end, else the first.
pub fn strike(previous: Option<Exclusion>, epoch: u64) -> Exclusion {
    let strikes = match previous {
        Some(previous) if epoch < previous.until.saturating_add(RELAPSE_EPOCHS) => {
            previous.strikes.saturating_add(1)
        }
        _ => 1,
    };
    Exclusion {
        strikes,
        from: epoch,
        until: epoch.saturating_add(exclusion_epochs(strikes)),
    }
}

fn record_key(filter: &[u8], member: &[u8]) -> Result<Vec<u8>> {
    let mut key = Vec::new();
    put_bytes(&mut key, filter)?;
    key.extend_from_slice(member);
    Ok(key)
}

/// The latest exclusion of `member` from `filter`'s sessions, in effect or
/// not.
pub fn exclusion(state: &impl Records, filter: &[u8], member: &[u8]) -> Result<Option<Exclusion>> {
    read(state, EXCLUSION, &record_key(filter, member)?)?
        .map(|bytes| Exclusion::decode(&bytes))
        .transpose()
}

pub(super) fn set_exclusion(
    state: &HypergraphState,
    frame: u64,
    filter: &[u8],
    member: &[u8],
    value: &Exclusion,
) -> Result<()> {
    write(
        state,
        frame,
        EXCLUSION,
        &record_key(filter, member)?,
        &value.encode(),
    )
}

/// `desired`, the provers eligible for `filter`'s next session at GLOBAL
/// frame `frame`, less the members excluded in its epoch. Unchanged before
/// [`super::presence_exclusion_frame`], and unchanged if the exclusions
/// would leave fewer than [`MIN_COMMITTEE`] members: the floor suspends
/// them rather than seat too small a committee.
pub fn seated(
    state: &impl Records,
    frame: u64,
    filter: &[u8],
    desired: Vec<Vec<u8>>,
) -> Result<Vec<Vec<u8>>> {
    if frame < super::presence_exclusion_frame() {
        return Ok(desired);
    }
    let epoch = quil_types::consensus::epoch_for_frame(frame);
    let mut kept = Vec::with_capacity(desired.len());
    for member in &desired {
        if !exclusion(state, filter, member)?.is_some_and(|excluded| excluded.covers(epoch)) {
            kept.push(member.clone());
        }
    }
    if kept.len() == desired.len() || kept.len() < MIN_COMMITTEE {
        return Ok(desired);
    }
    Ok(kept)
}

/// A session [`evaluate`] excluded members of: fence it early and seat
/// `committee` ([`super::schedule::fence_absent`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub filter: Vec<u8>,
    /// The stalled session's ID.
    pub session: [u8; 32],
    /// Its successor's committee: the eligible provers less the excluded,
    /// sorted.
    pub committee: Vec<Vec<u8>>,
    /// The members to exclude.
    pub excluded: Vec<Vec<u8>>,
    /// Their exclusions, written only once the session is fenced
    /// ([`super::schedule::fence_absent`]).
    pub strikes: Vec<Exclusion>,
}

impl Decision {
    /// The excluded provers for a log line: address, strike and the epoch
    /// each is seated again, at most [`LOGGED_MEMBERS`].
    pub fn describe_strikes(&self) -> Vec<String> {
        self.excluded
            .iter()
            .zip(&self.strikes)
            .take(LOGGED_MEMBERS)
            .map(|(member, next)| {
                format!(
                    "{} (strike {}, until epoch {})",
                    describe(member),
                    next.strikes,
                    next.until
                )
            })
            .collect()
    }
}

/// A prover address for logs: the Poseidon of the member's key.
fn describe(member: &[u8]) -> String {
    crate::global_intrinsic::materialize::prover_address_from_pubkey(member)
        .map(hex::encode)
        .unwrap_or_default()
}

/// Members named in one log line at most.
const LOGGED_MEMBERS: usize = 16;

fn skip(frame: u64, filter: &[u8], session: &Session, present: usize, reason: &'static str) {
    tracing::info!(
        frame,
        filter = hex::encode(filter),
        generation = session.generation,
        members = session.members.len(),
        present,
        quorum = quorum(session.members.len()),
        reason,
        "committee presence: stalled session's absent members not excluded",
    );
}

/// The epoch's exclusion pass, at its first maintenance pass ([`evaluates`];
/// otherwise nothing): for each of `filters`' head sessions with a presence
/// record for the previous epoch, decide whether excluding its absent
/// members unlocks quorum, and return those sessions with their committees
/// and strikes. Writes nothing: [`super::schedule::fence_absent`] fences
/// each and records its strikes together, or neither. `desired` gives a
/// filter's eligible provers, as the membership pass seats them.
///
/// A session is considered only if its executed tip did not advance, nor
/// the session start, after the previous epoch's first frame, if it is
/// active or closing for a membership change, and if its present members
/// (notarize or nullify) do not exceed its quorum but are a strict majority
/// of its members. Its successor's committee is then `desired`
/// less the members already excluded and those of its members without a
/// presence mark; eligible provers that are not its members are kept but not
/// counted present. The absent members are struck only if that committee
/// has at least [`MIN_COMMITTEE`] members and its present members reach its
/// quorum, and only if some eligible member is absent. A skipped session
/// logs its reason; an excluding one is logged with its fence.
pub fn evaluate(
    state: &HypergraphState,
    frame: u64,
    filters: &[Vec<u8>],
    desired: &mut dyn FnMut(&[u8]) -> Result<Vec<Vec<u8>>>,
) -> Result<Vec<Decision>> {
    let mut decisions = Vec::new();
    if !evaluates(frame) {
        return Ok(decisions);
    }
    let epoch = quil_types::consensus::epoch_for_frame(frame);
    let Some(previous) = epoch.checked_sub(1) else {
        return Ok(decisions);
    };
    let previous_start = previous.saturating_mul(quil_types::consensus::epoch_length_frames());
    for filter in filters {
        let Some(session) = head(state, filter)? else {
            continue;
        };
        let id = session.id()?;
        // Present: a notarize or, protecting its signer only, a nullify of
        // the session recorded in the previous epoch.
        let notarized = presence::present(state, &session, previous)?;
        let nullified = presence::protected(state, &session, previous)?;
        if notarized.is_none() && nullified.is_none() {
            continue;
        }
        let marked = |marks: &Option<Vec<bool>>, index: usize| {
            marks
                .as_ref()
                .is_some_and(|marks| marks.get(index).copied().unwrap_or(false))
        };
        let marks: Vec<bool> = (0..session.members.len())
            .map(|index| marked(&notarized, index) || marked(&nullified, index))
            .collect();
        let voters = marks.iter().filter(|&&mark| mark).count();
        match status(state, &id)? {
            Status::Closed(_) => continue,
            Status::Active => {}
            Status::Sealing(request_id) => {
                let pending = super::request(state, &request_id)?.ok_or_else(|| {
                    QuilError::Store("closing session's request is absent".into())
                })?;
                if !super::schedule::membership_request(&pending, filter) {
                    skip(
                        frame,
                        filter,
                        &session,
                        voters,
                        "closing for a split or merge",
                    );
                    continue;
                }
            }
        }
        if session_tip_frame(state, &id)?.is_some_and(|tip| tip > previous_start) {
            skip(
                frame,
                filter,
                &session,
                voters,
                "its executed tip advanced, or it started, during the epoch",
            );
            continue;
        }
        // With present members to spare beyond its quorum, absence alone
        // does not stall the session; at its quorum exactly, any one more
        // failure does.
        if voters > quorum(session.members.len()) {
            skip(
                frame,
                filter,
                &session,
                voters,
                "its present members exceed its quorum: absence does not stall it",
            );
            continue;
        }
        // One reporter's view decides nothing: a submitter that saw few
        // votes, or carried only its friends', would make the rest look
        // absent. The present members must be a strict majority of the
        // session's, whom every member may report itself
        // (`quil_engine::presence_reports`).
        if voters * 2 <= session.members.len() {
            skip(
                frame,
                filter,
                &session,
                voters,
                "its present members are not a majority of its members",
            );
            continue;
        }
        let eligible = desired(filter.as_slice())?;
        if eligible.is_empty() {
            skip(frame, filter, &session, voters, "no prover is eligible");
            continue;
        }
        let mark = |member: &[u8]| {
            session
                .members
                .binary_search_by(|probe| probe.as_slice().cmp(member))
                .ok()
                .map(|index| marks[index])
        };
        let mut committee = Vec::with_capacity(eligible.len());
        let mut absent = Vec::new();
        for member in eligible {
            if exclusion(state, filter, &member)?.is_some_and(|excluded| excluded.covers(epoch)) {
                continue;
            }
            match mark(member.as_slice()) {
                Some(false) => absent.push(member),
                _ => committee.push(member),
            }
        }
        if absent.is_empty() {
            skip(
                frame,
                filter,
                &session,
                voters,
                "no eligible member is absent",
            );
            continue;
        }
        if committee.len() < MIN_COMMITTEE {
            skip(
                frame,
                filter,
                &session,
                voters,
                "the committee without its absent members would fall below the consensus minimum",
            );
            continue;
        }
        let present = committee
            .iter()
            .filter(|member| mark(member.as_slice()) == Some(true))
            .count();
        if present < quorum(committee.len()) {
            skip(frame, filter, &session, voters, "its present members would not reach quorum of the committee without its absent members");
            continue;
        }
        let mut strikes = Vec::with_capacity(absent.len());
        for member in &absent {
            strikes.push(strike(exclusion(state, filter, member)?, epoch));
        }
        decisions.push(Decision {
            filter: filter.clone(),
            session: id,
            committee,
            excluded: absent,
            strikes,
        });
    }
    Ok(decisions)
}

/// An excluded member's sign of life: its Falcon signature, under
/// [`CLAIM_DOMAIN`], over the filter and the storage beacon of a GLOBAL
/// frame earlier in the epoch it is included in ([`claim_message`]). The
/// GLOBAL operation [`TYPE_PRESENCE_REPORT`], version [`CLAIM_VERSION`].
/// Accepted only while it ends an exclusion of the member in effect beyond
/// the next epoch boundary ([`apply_claim`]), so one claim per exclusion.
/// No node builds claims: they are submitted by hand.
///
/// Encoding: type prefix ‖ version ‖ filter ‖ member key (897 bytes) ‖
/// anchor (u64) ‖ signature (666 bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceClaim {
    pub filter: Vec<u8>,
    pub member: Vec<u8>,
    pub anchor: u64,
    pub signature: Vec<u8>,
}

/// The message a [`PresenceClaim`] signs: the filter, the anchor frame and
/// its storage beacon (ρ_N of its output).
pub fn claim_message(filter: &[u8], anchor: u64, anchor_output: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    put_bytes(&mut out, filter)?;
    out.extend_from_slice(&anchor.to_be_bytes());
    out.extend_from_slice(&quil_crypto::porep::derive_storage_beacon(
        anchor,
        anchor_output,
    ));
    Ok(out)
}

impl PresenceClaim {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = TYPE_PRESENCE_REPORT.to_be_bytes().to_vec();
        out.push(CLAIM_VERSION);
        put_bytes(&mut out, &self.filter)?;
        out.extend_from_slice(&self.member);
        out.extend_from_slice(&self.anchor.to_be_bytes());
        out.extend_from_slice(&self.signature);
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(bytes)?;
        c.magic(&TYPE_PRESENCE_REPORT.to_be_bytes())?;
        if c.u8()? != CLAIM_VERSION {
            return Err(invalid("not a presence claim"));
        }
        let filter = c.bytes(MAX_FILTER_BYTES)?;
        let member = c.take(quil_crypto::FALCON_PUBLIC_KEY_LEN)?.to_vec();
        let anchor = c.u64()?;
        let signature = c.take(quil_crypto::FALCON_SIGNATURE_LEN)?.to_vec();
        c.finish()?;
        let claim = Self {
            filter,
            member,
            anchor,
            signature,
        };
        claim.validate()?;
        Ok(claim)
    }

    fn validate(&self) -> Result<()> {
        if !(32..=MAX_FILTER_BYTES).contains(&self.filter.len()) {
            return Err(invalid("invalid full shard filter length"));
        }
        if self.member.len() != quil_crypto::FALCON_PUBLIC_KEY_LEN
            || self.signature.len() != quil_crypto::FALCON_SIGNATURE_LEN
        {
            return Err(invalid("claim key or signature has the wrong length"));
        }
        if self.anchor == 0 {
            return Err(invalid("claim names no anchor frame"));
        }
        Ok(())
    }
}

/// Refuse every claim before [`super::presence_exclusion_frame`].
pub fn require_claims_active(frame: u64) -> Result<()> {
    if frame < super::presence_exclusion_frame() {
        return Err(invalid(
            "claims are not accepted before the presence exclusion frame",
        ));
    }
    Ok(())
}

/// Validate `claim` for inclusion in GLOBAL frame `frame`, without writing,
/// and return the exclusion it ends. Its anchor must be an earlier frame of
/// `frame`'s epoch, checked before `anchor_output` is asked for it, as for a
/// presence report.
pub fn verify_claim(
    state: &impl Records,
    frame: u64,
    claim: &PresenceClaim,
    anchor_output: impl Fn(u64) -> Result<Vec<u8>>,
) -> Result<Exclusion> {
    require_claims_active(frame)?;
    claim.validate()?;
    let epoch = quil_types::consensus::epoch_for_frame(frame);
    if claim.anchor >= frame || quil_types::consensus::epoch_for_frame(claim.anchor) != epoch {
        return Err(invalid(
            "anchor is not an earlier frame of the inclusion epoch",
        ));
    }
    let current = exclusion(state, &claim.filter, &claim.member)?
        .filter(|excluded| excluded.covers(epoch) && excluded.until > epoch.saturating_add(1))
        .ok_or_else(|| {
            invalid("no exclusion of the member on the filter lasts past the next epoch boundary")
        })?;
    let output = anchor_output(claim.anchor)?;
    let message = claim_message(&claim.filter, claim.anchor, &output)?;
    if !quil_crypto::falcon_verify(&claim.member, &claim.signature, &message, CLAIM_DOMAIN) {
        return Err(invalid(
            "claim signature does not verify under the member's key",
        ));
    }
    Ok(current)
}

/// Execute `claim` in GLOBAL frame `frame`: [`verify_claim`] it, and end the
/// member's exclusion at the next epoch boundary, keeping its strikes.
pub fn apply_claim(
    state: &HypergraphState,
    frame: u64,
    claim: &PresenceClaim,
    anchor_output: impl Fn(u64) -> Result<Vec<u8>>,
) -> Result<()> {
    let current = verify_claim(state, frame, claim, anchor_output)?;
    let epoch = quil_types::consensus::epoch_for_frame(frame);
    let cleared = Exclusion {
        until: epoch.saturating_add(1),
        ..current
    };
    super::atomic(state, || {
        set_exclusion(state, frame, &claim.filter, &claim.member, &cleared)
    })?;
    tracing::info!(
        frame,
        filter = hex::encode(&claim.filter),
        prover = describe(&claim.member),
        strikes = current.strikes,
        excluded_until = current.until,
        seated_from = cleared.until,
        "committee presence: an excluded member signed in; it is seated again from the next epoch boundary",
    );
    Ok(())
}
