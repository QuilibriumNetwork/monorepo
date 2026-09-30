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
    QuilError::InvalidSignature(format!("app session certificate: {message}"))
}

/// `None` permits the explicitly legacy, generation-zero verifier only when
/// this application has never entered the handoff protocol. A missing positive
/// generation, corrupt index or read failure must never select that fallback.
pub fn verify(
    state: &impl Records,
    claim: &FrameClaim<'_>,
    bytes: &[u8],
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
            return Err(invalid("generation has no authorization"));
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
        if claim.frame > end.frame
            || claim.view > end.view
            || (claim.frame == end.frame && (claim.view != end.view || claim.digest != end.digest))
            || (claim.frame < end.frame && claim.view >= end.view)
        {
            return Err(invalid("data frame is outside the terminal checkpoint"));
        }
    }
    Ok(Some(VerifiedFrame {
        session,
        certificate,
    }))
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
