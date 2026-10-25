//! Verification of data-frame certificates against historical authorization.
//!
//! This does not validate a frame's body/output, install a consensus session,
//! or establish local bootstrap readiness. Callers perform those checks at
//! their respective execution/consensus boundaries.

use quil_cw_consensus::app_cert::{unverified_finalization_epoch, VerifiedFinalization};
use quil_cw_consensus::handoff::Session;
use quil_types::error::{QuilError, Result};

use super::{head, manages_application, session_at_generation, submitted_checkpoint, Records};

#[derive(Clone, Copy)]
pub struct FrameClaim<'a> {
    pub filter: &'a [u8],
    pub frame: u64,
    pub view: u64,
    pub parent: &'a [u8],
    /// The caller must reproduce the frame's deterministic output before
    /// treating the other header fields as authenticated by this digest.
    pub digest: [u8; 32],
}

pub struct VerifiedFrame {
    pub session: Session,
    pub certificate: VerifiedFinalization,
}

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidSignature(format!("{CERTIFICATE_REFUSED}{message}"))
}

const CERTIFICATE_REFUSED: &str = "app session certificate: ";

/// Why a frame whose generation the state read holds no session for is
/// refused.
const UNAUTHORIZED_GENERATION: &str = "generation has no authorization";

/// Whether `error` refused a frame because the state it was verified against
/// holds no session for its generation ([`verify`], [`verify_history`],
/// [`verify_discarded_base_frame`]). Unlike the other refusals, which the
/// session decides, a later GLOBAL frame can still authorize that generation.
pub fn unauthorized_generation(error: &QuilError) -> bool {
    matches!(error, QuilError::InvalidSignature(message)
        if message.strip_prefix(CERTIFICATE_REFUSED) == Some(UNAUTHORIZED_GENERATION))
}

/// `None` permits the explicitly legacy, generation-zero verifier only when
/// this application has never entered the handoff protocol. A missing positive
/// generation, corrupt index or read failure must never select that fallback.
pub fn verify(
    state: &impl Records,
    claim: &FrameClaim<'_>,
    bytes: &[u8],
) -> Result<Option<VerifiedFrame>> {
    verify_with(state, claim, bytes, false)
}

/// [`verify`] for a data frame read as history (archive ingest, followers,
/// sync), which also accepts the data frame a re-seal checkpoints. A re-seal
/// (`HandoffProposer::with_seal_parents`) names the notarized seal it extends
/// as `checkpoint.view`, so that data frame was certified at a lower view;
/// it is the session tip GLOBAL executed and matched with the checkpoint's
/// frame and digest before accepting the seal. GLOBAL header execution keeps
/// [`verify`], whose outcomes must not change. Every archive refused frame
/// 7078 of a re-sealed …000508 session and GLOBAL halted at 874,887
/// (2026-10-11).
pub fn verify_history(
    state: &impl Records,
    claim: &FrameClaim<'_>,
    bytes: &[u8],
) -> Result<Option<VerifiedFrame>> {
    verify_with(state, claim, bytes, true)
}

/// The first data frame of a session GLOBAL ended at its base (sealed or
/// fenced there, none of its frames executed): certified by that session's
/// committee, frame `base_frame + 1` over its genesis, and past its terminal
/// checkpoint, so [`verify_history`] refuses it. A header's state roots are
/// its pre-state, which each voter checked against its own state before it
/// voted, so this frame attests the session's base state as its certifying
/// quorum held it. The frame itself stays discarded.
pub fn verify_discarded_base_frame(
    state: &impl Records,
    claim: &FrameClaim<'_>,
    bytes: &[u8],
) -> Result<Session> {
    let generation =
        unverified_finalization_epoch(bytes).ok_or_else(|| invalid("malformed proposal prefix"))?;
    if generation == 0 {
        return Err(invalid("a legacy frame attests no session base"));
    }
    let session = session_at_generation(state, claim.filter, generation)?
        .ok_or_else(|| invalid(UNAUTHORIZED_GENERATION))?;
    let certificate = quil_cw_consensus::app_cert::check_finalization(
        bytes, &session.members, &session.namespace()?, claim.digest,
    )
    .map_err(|reason| invalid(&format!("generation {generation}: {reason}")))?;
    let proposal = &certificate.finalization.proposal;
    if proposal.round.epoch().get() != session.generation
        || proposal.round.view().get() != claim.view
        || claim.frame != session.base_frame + 1
        || !proposal.parent.is_zero()
        || claim.parent != session.genesis
    {
        return Err(invalid("frame is not the certified first frame of its session"));
    }
    let ended_at_base = submitted_checkpoint(state, &session.id()?)?
        .is_some_and(|end| end.frame == session.base_frame && end.digest == session.genesis);
    if !ended_at_base {
        return Err(invalid("session did not end at its base"));
    }
    Ok(session)
}

fn verify_with(
    state: &impl Records,
    claim: &FrameClaim<'_>,
    bytes: &[u8],
    history: bool,
) -> Result<Option<VerifiedFrame>> {
    let generation =
        unverified_finalization_epoch(bytes).ok_or_else(|| invalid("malformed proposal prefix"))?;
    // Legacy history (at or below a generation-0 source's base, or on a shard
    // still pending registration) keeps the legacy verifier.
    if generation == 0 && super::legacy::is_legacy_history(state, claim.filter, claim.frame)? {
        return Ok(None);
    }
    let Some(session) = session_at_generation(state, claim.filter, generation)? else {
        if generation != 0
            || manages_application(state, claim.filter)?
            || head(state, claim.filter)?.is_some()
        {
            return Err(invalid(UNAUTHORIZED_GENERATION));
        }
        return Ok(None);
    };
    let certificate = quil_cw_consensus::app_cert::check_finalization(
        bytes, &session.members, &session.namespace()?, claim.digest,
    )
    .map_err(|reason| invalid(&format!("generation {generation}: {reason}")))?;
    let proposal = &certificate.finalization.proposal;
    if proposal.round.epoch().get() != session.generation
        || proposal.round.view().get() != claim.view
        || claim.frame <= session.base_frame
        || claim.parent.len() != 32
    {
        return Err(invalid(
            "frame coordinates differ from authorization/certificate",
        ));
    }
    if session.generation == 0 {
        // A legacy committee's Simplex instance restarts at each member's local
        // head, so a zero parent view can appear at any frame; its frames chain
        // through their parent selectors, which the frame validator checks.
    } else if claim.frame == session.base_frame + 1 {
        if !proposal.parent.is_zero() || claim.parent != session.genesis {
            return Err(invalid(
                "first data frame does not extend authorized genesis",
            ));
        }
    } else if proposal.parent.is_zero() {
        return Err(invalid("noninitial data frame names the virtual genesis"));
    }

    // A terminal certificate can arrive before the remaining source shards
    // close. Its cutoff applies immediately, including to historical replay.
    if let Some(end) = submitted_checkpoint(state, &session.id()?)? {
        if (claim.frame > end.frame
            || claim.view > end.view
            || (claim.frame == end.frame && (claim.view != end.view || claim.digest != end.digest))
            || (claim.frame < end.frame && claim.view >= end.view))
            && !(history && resealed_tip(state, &session, claim, &end)?)
        {
            return Err(invalid("data frame is outside the terminal checkpoint"));
        }
    }
    Ok(Some(VerifiedFrame {
        session,
        certificate,
    }))
}

/// The data frame a re-seal checkpoints: its frame and digest, certified
/// below the checkpoint's view, and exactly the session's executed tip.
fn resealed_tip(
    state: &impl Records,
    session: &Session,
    claim: &FrameClaim<'_>,
    end: &quil_cw_consensus::handoff::Checkpoint,
) -> Result<bool> {
    if claim.frame != end.frame || claim.digest != end.digest || claim.view >= end.view {
        return Ok(false);
    }
    Ok(super::session_tip(state, &session.id()?)?
        .is_some_and(|tip| (tip.frame, tip.view, tip.digest) == (claim.frame, claim.view, claim.digest)))
}

/// Under a committee-handoff flag day (`LegacyHistory::Discard`) the legacy
/// verifier accepts nothing GLOBAL executes from activation on, whether or
/// not the application ever received a session: legacy history was
/// discarded, and every shard runs an authorized session from there.
pub fn refuse_legacy_after_flag_day(global_frame: u64) -> Result<()> {
    match quil_types::consensus::committee_handoff_policy() {
        Some(policy)
            if policy.legacy_history == quil_types::consensus::LegacyHistory::Discard
                && global_frame >= policy.activation_frame =>
        {
            Err(QuilError::InvalidSignature(
                "legacy app certificates are not accepted after the committee-handoff flag day".into(),
            ))
        }
        _ => Ok(()),
    }
}

/// [`require_unregistered`], except that legacy history (see
/// [`super::legacy::is_legacy_history`]) keeps its legacy certificates.
pub fn require_legacy_allowed(state: &impl Records, filter: &[u8], frame: u64) -> Result<()> {
    if super::legacy::is_legacy_history(state, filter, frame)? {
        return Ok(());
    }
    require_unregistered(state, filter)
}

/// Legacy aggregate signatures cannot bypass an installed session's quorum.
pub fn require_unregistered(state: &impl Records, filter: &[u8]) -> Result<()> {
    if manages_application(state, filter)? || head(state, filter)?.is_some() {
        return Err(invalid(
            "authorized session requires its Simplex certificate",
        ));
    }
    Ok(())
}
