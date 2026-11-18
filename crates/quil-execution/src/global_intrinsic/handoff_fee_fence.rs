//! Fee vote fence: GLOBAL fences an app-shard session whose quorum
//! certified a frame voting out of bounds, at the session's executed tip.
//!
//! From the fee vote bound frame (`crate::fee_vote`), members and sync refuse
//! a frame whose fee vote lies outside the bounds at its anchor, and GLOBAL
//! never executes one. A quorum of members on builds without the bound still
//! certifies such a frame and extends it, and GLOBAL, which executes a
//! session's headers without reading their parents, would keep executing
//! its descendants: the session's executed tip would pass a frame the
//! members carrying the bound, new members and archives refuse, and they
//! would wait on it for good. Instead, the certified header is GLOBAL's
//! evidence: executing it fences the session at its executed tip, below the
//! refused frame, through the early fence path
//! ([`super::schedule::fence_early`]), and authorizes its successor from
//! that tip with the session's committee, or the one its pending membership
//! change names. Nothing of the frame executes
//! (no tip, credit, outflow or reward), and GLOBAL refuses the session's
//! frames past the fence, the refused frame's descendants among them.
//! Members date the fence by the frame GLOBAL records for it
//! ([`super::schedule::fence_frame`]), as for any early fence.
//!
//! Only a frame certified by the session's quorum fences it, and only a
//! frame above its executed tip: once GLOBAL executed a frame at or above
//! the refused one, the fence would name a descendant of it, and the header
//! is refused as before. A frame its quorum finalized only through a
//! certified descendant carries no certificate of its own and fences
//! nothing either: GLOBAL leaders carrying the bound hold that descendant
//! back for the refused frame's body, and the session waits for its next
//! membership change's timeout ([`super::schedule::fence_stalled_sources`]). A session closing for a split or merge, or whose
//! shard a pending split or merge reserves, is not fenced either: its
//! header is refused, and the change's own timeout fences it. Everything
//! here is GLOBAL consensus from the fee vote bound frame, judged by the
//! header's anchor.

use quil_types::error::Result;

use super::schedule::{fence_early, membership_request, EarlyFence};
use super::{head, invalid, request, session_tip, status, Records, Status};
use crate::hypergraph_state::HypergraphState;

/// The committee the successor of `filter`'s head session `id` takes when
/// GLOBAL fences it for a frame `frame` voting out of bounds, after checking
/// that the fence applies: the session's own members, or those its pending
/// membership request names. An `InvalidArgument` error refuses the header.
pub fn check(
    state: &impl Records,
    id: &[u8; 32],
    filter: &[u8],
    frame: u64,
) -> Result<Vec<Vec<u8>>> {
    let session = head(state, filter)?
        .filter(|session| session.id().is_ok_and(|head| head == *id))
        .ok_or_else(|| invalid("fee vote fence: the certifying session is not its shard's head"))?;
    if let Some(tip) = session_tip(state, id)? {
        if tip.frame >= frame {
            return Err(invalid(&format!(
                "fee vote fence: GLOBAL executed frame {} of the session, at or above frame {frame} \
                 voting out of bounds",
                tip.frame
            )));
        }
    }
    match status(state, id)? {
        Status::Active => Ok(session.members),
        Status::Sealing(request_id) => request(state, &request_id)?
            .filter(|pending| membership_request(pending, filter))
            .map(|pending| pending.targets[0].committee.members.clone())
            .ok_or_else(|| invalid("fee vote fence: the session is closing for a split or merge")),
        Status::Closed(_) => Err(invalid("fee vote fence: the session has ended")),
    }
}

/// Fence `filter`'s head session `id`, which certified frame `frame` voting
/// `vote` out of bounds at anchor `anchor`, at its executed tip and authorize
/// its successor ([`check`], [`fence_early`]); GLOBAL frame `global_frame`
/// executes it. Returns the fence's frame. An `InvalidArgument` error refuses
/// the header with nothing written.
pub fn fence(
    state: &HypergraphState,
    global_frame: u64,
    id: &[u8; 32],
    filter: &[u8],
    frame: u64,
    vote: u64,
    anchor: u64,
) -> Result<u64> {
    let committee = check(state, id, filter, frame)?;
    let fenced = match fence_early(state, global_frame, filter, id, &committee)? {
        EarlyFence::Fenced(fenced) => fenced,
        EarlyFence::Reserved(_) => {
            return Err(invalid(
                "fee vote fence: the shard is reserved by a pending split or merge",
            ))
        }
        EarlyFence::NotApplicable => {
            return Err(invalid(
                "fee vote fence: the session cannot be fenced early",
            ))
        }
    };
    tracing::warn!(
        frame = global_frame,
        filter = hex::encode(filter),
        generation = fenced.session.generation,
        members = fenced.session.members.len(),
        fenced_at = fenced.checkpoint.frame,
        refused_frame = frame,
        vote,
        anchor,
        bounds = %format!(
            "{}..={}",
            crate::fee_vote::MIN_FEE_MULTIPLIER_VOTE,
            crate::fee_vote::MAX_FEE_MULTIPLIER_VOTE
        ),
        request = hex::encode(fenced.request),
        "fee vote fence: a quorum certified a frame voting out of bounds; its session is fenced at its \
         executed tip and its successor authorized from there with its committee, or the one its pending \
         membership change names. Members on a build \
         without the bound vote for such frames: upgrade them"
    );
    Ok(fenced.checkpoint.frame)
}
