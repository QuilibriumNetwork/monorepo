//! Terminal handoff proposals over the ordinary application frame proposer.
//!
//! The parent reader is a trusted application boundary: it must authenticate the
//! globally authorized session/request and return durably materialized DATA
//! state, including outgoing history, for the selected parent. A header's
//! pre-state roots, the latest local clock head, or a seal itself cannot supply
//! that state. Read/sync failures must return an error, never an empty checkpoint.

use std::sync::Arc;

use quil_types::error::Result;

use crate::adapters::{digest_from_identity, BlockStore, Digest, GlobalProposer, Liveness, ProposalContext, Step};

use super::{Checkpoint, Seal, Session};

/// One consistent, authorized view of the selected materialized data parent.
/// A pending request causes leaders to propose a seal; previously proposed data
/// frames can still be verified while that request is pending.
#[derive(Clone, Debug)]
pub struct AuthorizedParent {
    pub checkpoint: Checkpoint,
    pub closing_request: Option<[u8; 32]>,
}

/// Called for both proposal production and voting, including after restart.
/// The reader must reject retired sessions and incomplete state/history. Its
/// checkpoint must identify a data frame (or the authorized virtual genesis),
/// so descendants of a terminal seal fail even without local seal history;
/// the only exception is a re-seal ([`HandoffProposer::with_seal_parents`]).
pub type ParentReader = Arc<dyn Fn(ProposalContext) -> Result<AuthorizedParent> + Send + Sync>;

/// Reconstruct a seal's data checkpoint through bounded private execution.
/// The reader must authenticate the current session and closing request and
/// derive state and history locally; the supplied roots are never trusted.
pub type CheckpointReader = Arc<dyn Fn(ProposalContext, &Checkpoint) -> Result<AuthorizedParent> + Send + Sync>;

pub struct HandoffProposer {
    inner: Arc<dyn GlobalProposer>,
    session: Session,
    session_id: [u8; 32],
    read_parent: ParentReader,
    /// Authorizes a selected parent that is notarized but not yet
    /// materialized, from a private execution of it. A leader uses it only
    /// after its waits; a voter uses it at once.
    read_private_parent: Option<ParentReader>,
    read_private_checkpoint: Option<CheckpointReader>,
    /// View whose parent this leader could not read yet, and how often it asked.
    parent_waits: std::sync::Mutex<(u64, u32)>,
    /// Where this member's reasons for declining and refusing are noted.
    liveness: Option<Arc<Liveness>>,
    /// Re-sealing ([`Self::with_seal_parents`]): the proposal bodies this
    /// member holds, and the authorized checkpoint at its materialized tip
    /// whatever the selection.
    seal_parents: Option<(BlockStore, ParentReader)>,
    /// Told, for each seal of this close it verifies, whether the seal's
    /// state roots equal its own ([`Self::with_checkpoint_votes`]).
    checkpoint_votes: Option<CheckpointVotes>,
}

/// Called with `true` when a verified seal's checkpoint equals this member's,
/// and `false` when it differs only in its state roots.
pub type CheckpointVotes = Arc<dyn Fn(bool) + Send + Sync>;

/// Why no authorized parent was found: a short reason and its specifics.
type Unauthorized = (&'static str, String);

/// The first bytes of a digest, in hex.
fn short(digest: &[u8; 32]) -> String {
    digest[..4].iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A new view opens when its parent is notarized; the leader materializes that
/// parent only once it is finalized, moments later. It asks again this many
/// times (250 ms apart) before giving the view up, so a member that is really
/// behind costs the committee seconds, not its whole leader timeout.
const PARENT_WAITS: u32 = 12;

impl HandoffProposer {
    pub fn new(
        inner: Arc<dyn GlobalProposer>,
        session: Session,
        read_parent: ParentReader,
    ) -> Result<Self> {
        let session_id = session.id()?;
        Ok(Self {
            inner,
            session,
            session_id,
            read_parent,
            read_private_parent: None,
            read_private_checkpoint: None,
            parent_waits: std::sync::Mutex::new((0, 0)),
            liveness: None,
            seal_parents: None,
            checkpoint_votes: None,
        })
    }

    /// Report each verified seal's agreement with this member's own state
    /// roots. At a session base no data frame is proposed, so a member whose
    /// committed state differs from everyone else's (a partial or stale
    /// download) only ever sees seals it refuses; this is how it learns that
    /// no one shares its roots, and re-installs its shard's data (a live
    /// shard: 34 members, about 20 on one root, each dissenter on its own).
    pub fn with_checkpoint_votes(mut self, votes: Option<CheckpointVotes>) -> Self {
        self.checkpoint_votes = votes;
        self
    }

    /// `proposed` against this member's `local` checkpoint: agreement, or a
    /// difference in the state roots alone. Anything else says nothing about
    /// this member's state.
    fn vote_roots(&self, proposed: &Checkpoint, local: &Checkpoint) {
        let Some(vote) = self.checkpoint_votes.as_ref() else { return };
        if proposed == local {
            vote(true);
        } else if (Checkpoint { state_roots: local.state_roots, ..proposed.clone() }) == *local {
            vote(false);
        }
    }

    /// Let a seal extend a notarized seal of the same checkpoint (a re-seal).
    ///
    /// A seal ends its session: nothing may build data on it, so only a
    /// finalization of its own view makes it final. A member that nullified
    /// that view can no longer finalize it, and Simplex keeps selecting the
    /// notarized seal as the parent of every later view. When more members
    /// nullified it than the quorum can spare, every later view was nullified
    /// until GLOBAL fenced the session, discarding its certified history
    /// (a live shard: seal notarized by 16 of quorum 16, finalized by 12).
    ///
    /// A re-seal is an ordinary [`Seal`] of the same request, session and
    /// checkpoint, at its own view, whose parent is the notarized seal. Its
    /// `checkpoint.view` names that parent's view, so GLOBAL verifies its
    /// finalization exactly as any other (`verify_seal`: the certified parent
    /// view equals `checkpoint.view`; the frame and digest are the executed
    /// tip's). Above a seal at the session base (the genesis at view zero)
    /// GLOBAL accepts one only from its seal recovery frame
    /// (`verify_seal_with`); until then it waits, resubmitted, as a fenced
    /// session would. Voters accept one only above a seal whose request,
    /// session and checkpoint frame, digest, roots and history equal their own
    /// authorized tip's, so every finalized chain still ends at that frame.
    ///
    /// `blocks` holds the seal bodies this member built or voted for (kept
    /// across restarts); `tip` reads the authorized checkpoint at the local
    /// materialized tip, ignoring the selected parent.
    pub fn with_seal_parents(mut self, blocks: BlockStore, tip: ParentReader) -> Self {
        self.seal_parents = Some((blocks, tip));
        self
    }

    pub fn with_private_reader(mut self, reader: Option<ParentReader>) -> Self {
        self.read_private_parent = reader;
        self
    }

    /// Authorize a re-seal above the committed tip through private execution
    /// of its underlying data. Exact checkpoint and closing-request equality
    /// is still required; this never repairs a same-height disagreement.
    pub fn with_private_checkpoint_reader(mut self, reader: Option<CheckpointReader>) -> Self {
        self.read_private_checkpoint = reader;
        self
    }

    /// Note in `liveness` why this member declines a turn or refuses a vote.
    pub fn with_liveness(mut self, liveness: Option<Arc<Liveness>>) -> Self {
        self.liveness = liveness;
        self
    }

    fn note(&self, step: Step, context: ProposalContext, reason: &'static str, detail: String) {
        if let Some(liveness) = self.liveness.as_ref() {
            liveness.note(step, context.view, reason, detail);
        }
    }

    /// The committed parent, else, when allowed, a private execution of it;
    /// and whether it is the committed one.
    fn parent_or_private(&self, context: ProposalContext, private: bool) -> std::result::Result<(AuthorizedParent, bool), Unauthorized> {
        match self.checked_parent(context, &self.read_parent) {
            Ok(parent) => Ok((parent, true)),
            Err((reason, committed)) => {
                let Some(reader) = self.read_private_parent.as_ref().filter(|_| private) else {
                    return Err((reason, committed));
                };
                self.checked_parent(context, reader)
                    .map(|parent| (parent, false))
                    .map_err(|(reason, private)| (reason, format!("{committed}; unfinalized: {private}")))
            }
        }
    }

    fn checked_parent(&self, context: ProposalContext, reader: &ParentReader) -> std::result::Result<AuthorizedParent, Unauthorized> {
        if context.epoch != self.session.generation {
            return Err(("epoch is not the session's generation",
                format!("epoch {}, generation {}", context.epoch, self.session.generation)));
        }
        if context.view <= context.parent_view {
            return Err(("view not above its parent's",
                format!("view {}, parent view {}", context.view, context.parent_view)));
        }
        let parent = (reader)(context).map_err(|error| ("parent unavailable", error.to_string()))?;
        let checkpoint = &parent.checkpoint;
        let differs = |what: &str| ("parent differs from the authorized checkpoint", format!(
            "{what}: checkpoint frame {} view {} {}, selected view {} {}",
            checkpoint.frame, checkpoint.view, short(&checkpoint.digest),
            context.parent_view, short(&context.parent.0),
        ));
        if checkpoint.view != context.parent_view || checkpoint.digest != context.parent.0 {
            return Err(differs("selection"));
        }
        if checkpoint.frame < self.session.base_frame {
            return Err(differs("below the session base"));
        }
        if checkpoint.frame == self.session.base_frame {
            // Generation zero's base is the registered legacy tip: a certified
            // frame at its own view, not a virtual genesis at view zero.
            let virtual_genesis = self.session.generation != 0;
            if (virtual_genesis && checkpoint.view != 0) || checkpoint.digest != self.session.genesis {
                return Err(differs("not the session genesis"));
            }
        } else if checkpoint.view == 0 {
            return Err(differs("view zero above the base"));
        }
        Ok(parent)
    }

    /// The selected parent, when it is a seal body this member holds.
    fn selected_seal(&self, context: ProposalContext) -> Option<Seal> {
        let (blocks, _) = self.seal_parents.as_ref()?;
        let bytes = blocks.get(&context.parent)?;
        if !Seal::is_encoding(&bytes) {
            return None;
        }
        // The digest names these exact bytes: the notarized block at the view.
        Seal::decode(&bytes).ok().filter(|seal| seal.digest() == context.parent.0)
    }

    /// The selected parent, when it is the seal of this member's own tip
    /// that it did not build or vote for (so holds no body of): the same
    /// request, session and checkpoint at the parent's view. Recognised by
    /// its digest alone, which the parent's notarization certifies. A re-seal
    /// of a re-seal still needs that parent's body.
    fn recognised_seal(&self, context: ProposalContext) -> Option<Seal> {
        let (_, read_tip) = self.seal_parents.as_ref()?;
        let tip = read_tip(context).ok()?;
        let seal = Seal {
            request: tip.closing_request?,
            session: self.session_id,
            view: context.parent_view,
            checkpoint: tip.checkpoint,
        };
        (seal.digest() == context.parent.0).then_some(seal)
    }

    fn propose_reseal(&self, context: ProposalContext, parent: &Seal) -> Option<(Digest, Vec<u8>)> {
        match self.reseal(context, parent, false) {
            Ok(seal) => {
                *self.parent_waits.lock().unwrap() = (context.view, 0);
                Some((digest_from_identity(seal.digest()), seal.encode()))
            }
            Err((reason, detail)) => {
                self.decline(context, reason, detail);
                None
            }
        }
    }

    /// Above a seal only its re-seal: nothing else continues a closed session.
    fn verify_reseal(&self, context: ProposalContext, parent: &Seal, digest: Digest, bytes: &[u8]) -> bool {
        let expected = match self.reseal(context, parent, true) {
            Ok(seal) => seal,
            Err((reason, detail)) => {
                self.note(Step::Verify, context, reason, detail);
                return false;
            }
        };
        if !Seal::is_encoding(bytes) {
            self.note(Step::Verify, context, "data frame above a terminal seal", String::new());
            return false;
        }
        let decoded = Seal::decode(bytes).ok();
        if let Some(seal) = decoded.as_ref().filter(|seal| seal.request == expected.request && seal.session == expected.session) {
            self.vote_roots(&seal.checkpoint, &expected.checkpoint);
        }
        let valid = decoded.is_some_and(|seal| seal == expected) && expected.digest() == digest.0;
        if !valid {
            self.note(Step::Verify, context, "re-seal differs from the local checkpoint", format!(
                "local frame {}, parent view {}", expected.checkpoint.frame, expected.checkpoint.view,
            ));
        }
        valid
    }

    /// The re-seal extending `parent`, a seal selected as the parent
    /// ([`Self::with_seal_parents`]): the same request, session and
    /// checkpoint, at this view, with `checkpoint.view` naming the parent's.
    /// When `voting`, a parent seal differing from the tip in its state roots
    /// alone counts as a disagreement ([`Self::with_checkpoint_votes`]).
    fn reseal(&self, context: ProposalContext, parent: &Seal, voting: bool) -> std::result::Result<Seal, Unauthorized> {
        let refused = |what: &str| ("seal parent differs from the authorized checkpoint", format!(
            "{what}: seal parent view {} frame {} {}", parent.view, parent.checkpoint.frame, short(&parent.checkpoint.digest),
        ));
        if context.epoch != self.session.generation {
            return Err(("epoch is not the session's generation",
                format!("epoch {}, generation {}", context.epoch, self.session.generation)));
        }
        if context.view <= context.parent_view {
            return Err(("view not above its parent's",
                format!("view {}, parent view {}", context.view, context.parent_view)));
        }
        if parent.session != self.session_id || parent.view != context.parent_view {
            return Err(refused("another session or view"));
        }
        let Some((_, read_tip)) = self.seal_parents.as_ref() else {
            return Err(("selected parent is a terminal seal", String::new()));
        };
        let mut tip = read_tip(context).map_err(|error| ("parent unavailable", error.to_string()))?;
        // A seal can be built above privately executed data that is notarized
        // but not finalized. Requiring that data to materialize before its
        // seal can finalize leaves every later view unable to extend it.
        // Reconstruct only a checkpoint above our tip; mismatching state at
        // the same height must continue to fail closed.
        if parent.checkpoint.frame > tip.checkpoint.frame {
            if let Some(read) = &self.read_private_checkpoint {
                tip = read(context, &parent.checkpoint)
                    .map_err(|error| ("seal checkpoint unavailable", error.to_string()))?;
            }
        }
        let Some(request) = tip.closing_request else {
            return Err(("seal parent while no closing request", String::new()));
        };
        if parent.request != request {
            return Err(refused("another request"));
        }
        let checkpoint = &tip.checkpoint;
        if parent.checkpoint.frame != checkpoint.frame
            || parent.checkpoint.digest != checkpoint.digest
            || parent.checkpoint.state_roots != checkpoint.state_roots
            || parent.checkpoint.history_root != checkpoint.history_root
        {
            if voting {
                self.vote_roots(&Checkpoint { view: checkpoint.view, ..parent.checkpoint.clone() }, checkpoint);
            }
            // The local frame tells a member behind the checkpoint from one
            // whose state differs at it.
            return Err(refused(&format!("checkpoint (local frame {} {})", checkpoint.frame, short(&checkpoint.digest))));
        }
        // A seal at the base names the genesis at view zero; its re-seal names
        // the genesis at the seal's view, which GLOBAL accepts only from its
        // seal recovery frame (`Seal::validate_with`). Generation zero never
        // seals at its base (a certified legacy frame).
        if checkpoint.frame <= self.session.base_frame && self.session.generation == 0 {
            return Err(("a seal at the session base cannot be re-sealed", String::new()));
        }
        Ok(Seal {
            request,
            session: self.session_id,
            view: context.view,
            checkpoint: Checkpoint { view: context.parent_view, ..checkpoint.clone() },
        })
    }

    /// Note why a turn was declined, and count the wait for its parent.
    fn decline(&self, context: ProposalContext, reason: &'static str, detail: String) {
        self.note(Step::Propose, context, reason, detail);
        let mut waits = self.parent_waits.lock().unwrap();
        *waits = if waits.0 == context.view { (context.view, waits.1 + 1) } else { (context.view, 1) };
    }
}

impl GlobalProposer for HandoffProposer {
    // This implementation requires the full context. Fabricating epoch/parent
    // coordinates from the old convenience interface would bypass its purpose.
    fn propose(&self, _view: u64, _parent: Digest) -> Option<(Digest, Vec<u8>)> {
        None
    }

    fn verify(
        &self,
        _view: u64,
        _parent: Digest,
        _digest: Digest,
        _bytes: Option<Vec<u8>>,
    ) -> bool {
        false
    }

    fn propose_retry(&self) -> Option<std::time::Duration> {
        let (_, waits) = *self.parent_waits.lock().unwrap();
        match waits {
            0 => self.inner.propose_retry(),
            1..=PARENT_WAITS => Some(std::time::Duration::from_millis(250)),
            _ => None,
        }
    }

    fn proposal_pacing(&self, context: ProposalContext) -> Option<std::time::Duration> {
        self.inner.proposal_pacing(context)
    }

    fn propose_with_context(&self, context: ProposalContext) -> Option<(Digest, Vec<u8>)> {
        if let Some(sealed) = self.selected_seal(context) {
            return self.propose_reseal(context, &sealed);
        }
        let waited = {
            let waits = self.parent_waits.lock().unwrap();
            waits.0 == context.view && waits.1 >= PARENT_WAITS
        };
        let (parent, committed) = match self.parent_or_private(context, waited) {
            Ok(parent) => parent,
            Err((reason, detail)) => {
                if let Some(sealed) = self.recognised_seal(context) {
                    return self.propose_reseal(context, &sealed);
                }
                self.decline(context, reason, detail);
                return None;
            }
        };
        *self.parent_waits.lock().unwrap() = (context.view, 0);
        if let Some(request) = parent.closing_request {
            // Seal only a checkpoint that finalized on its own (a committed
            // parent: one a finalized descendant made final is never the one
            // selected). A seal finalizes a notarized parent with no
            // certificate of its own, which no proof or drain carried to
            // GLOBAL, so GLOBAL refused the seal until it fenced the session
            // (eight sessions, 2026-10-15). Extend it with data instead: that
            // frame's finalization makes it final, and a later view seals
            // (decided 2026-10-16).
            if committed {
                let seal = Seal {
                    request,
                    session: self.session_id,
                    view: context.view,
                    checkpoint: parent.checkpoint,
                };
                return Some((digest_from_identity(seal.digest()), seal.encode()));
            }
            self.note(Step::Propose, context, "seal waits for a finalized checkpoint; proposing data", String::new());
        }
        let (digest, bytes) = self.inner.propose_with_context(context)?;
        // The data proposer cannot originate a seal outside the authorized path.
        if Seal::is_encoding(&bytes) {
            self.note(Step::Propose, context, "data proposer built a seal", String::new());
            return None;
        }
        Some((digest, bytes))
    }

    /// A data frame waits as the data proposer says (its GLOBAL anchor just
    /// ahead of this node); without this a member that receives the anchor
    /// moments after the leader refuses the proposal outright. A seal is
    /// checked at once.
    fn verify_delay(&self, context: ProposalContext, bytes: &[u8]) -> Option<std::time::Duration> {
        if Seal::is_encoding(bytes) {
            // A seal's checkpoint must have finalized here first (see
            // `propose_with_context`); it does moments after the view opens.
            let unfinalized = self.selected_seal(context).is_none()
                && self.checked_parent(context, &self.read_parent).is_err()
                && self.recognised_seal(context).is_none();
            return unfinalized.then_some(std::time::Duration::from_millis(250));
        }
        self.inner.verify_delay(context, bytes)
    }

    fn verify_with_context(
        &self,
        context: ProposalContext,
        digest: Digest,
        bytes: Option<Vec<u8>>,
    ) -> bool {
        let Some(bytes) = bytes else {
            tracing::debug!(view = context.view, parent_view = context.parent_view,
                session = %digest_from_identity(self.session_id), "handoff verify: proposal bytes unavailable");
            self.note(Step::Verify, context, "block not delivered", String::new());
            return false;
        };
        if let Some(sealed) = self.selected_seal(context) {
            return self.verify_reseal(context, &sealed, digest, &bytes);
        }
        let (parent, committed) = match self.parent_or_private(context, true) {
            Ok(parent) => parent,
            Err((reason, detail)) => {
                if let Some(sealed) = self.recognised_seal(context) {
                    return self.verify_reseal(context, &sealed, digest, &bytes);
                }
                self.note(Step::Verify, context, reason, detail);
                return false;
            }
        };
        if Seal::is_encoding(&bytes) {
            let Some(request) = parent.closing_request else {
                self.note(Step::Verify, context, "seal while no closing request", String::new());
                return false;
            };
            let Ok(seal) = Seal::decode(&bytes) else {
                self.note(Step::Verify, context, "undecodable seal", String::new());
                return false;
            };
            if seal.request == request && seal.session == self.session_id {
                self.vote_roots(&seal.checkpoint, &parent.checkpoint);
            }
            let valid = seal.request == request
                && seal.session == self.session_id
                && seal.view == context.view
                && seal.checkpoint == parent.checkpoint
                && seal.digest() == digest.0;
            if !valid {
                tracing::debug!(view = context.view, parent_view = context.parent_view,
                    session = %digest_from_identity(self.session_id),
                    request_matches = (seal.request == request),
                    session_matches = (seal.session == self.session_id),
                    view_matches = (seal.view == context.view),
                    digest_matches = (seal.digest() == digest.0),
                    proposed_frame = seal.checkpoint.frame, local_frame = parent.checkpoint.frame,
                    proposed_parent_view = seal.checkpoint.view, local_parent_view = parent.checkpoint.view,
                    parent_digest_matches = (seal.checkpoint.digest == parent.checkpoint.digest),
                    state_roots_match = (seal.checkpoint.state_roots == parent.checkpoint.state_roots),
                    proposed_history = %digest_from_identity(seal.checkpoint.history_root),
                    local_history = %digest_from_identity(parent.checkpoint.history_root),
                    "handoff verify: seal differs from the authorized local checkpoint");
                self.note(Step::Verify, context, "seal differs from the local checkpoint", format!(
                    "proposed frame {} view {}, local frame {} view {}, state roots match {}",
                    seal.checkpoint.frame, seal.checkpoint.view, parent.checkpoint.frame, parent.checkpoint.view,
                    seal.checkpoint.state_roots == parent.checkpoint.state_roots,
                ));
            }
            // A seal of a checkpoint that has not finalized here would finalize
            // it with no certificate of its own (see `propose_with_context`).
            if valid && !committed {
                self.note(Step::Verify, context, "seal of a checkpoint not finalized", format!(
                    "checkpoint frame {} view {}", parent.checkpoint.frame, parent.checkpoint.view,
                ));
                return false;
            }
            return valid;
        }
        self.inner.verify_with_context(context, digest, Some(bytes))
    }
}
