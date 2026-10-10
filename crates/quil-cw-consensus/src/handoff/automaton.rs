//! Terminal handoff proposals over the ordinary application frame proposer.
//!
//! The parent reader is a trusted application boundary: it must authenticate the
//! globally authorized session/request and return durably materialized DATA
//! state, including outgoing history, for the selected parent. A header's
//! pre-state roots, the latest local clock head, or a seal itself cannot supply
//! that state. Read/sync failures must return an error, never an empty checkpoint.

use std::sync::Arc;

use quil_types::error::Result;

use crate::adapters::{digest_from_identity, Digest, GlobalProposer, Liveness, ProposalContext, Step};

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
/// so descendants of a terminal seal fail even without local seal history.
pub type ParentReader = Arc<dyn Fn(ProposalContext) -> Result<AuthorizedParent> + Send + Sync>;

pub struct HandoffProposer {
    inner: Arc<dyn GlobalProposer>,
    session: Session,
    session_id: [u8; 32],
    read_parent: ParentReader,
    /// Authorizes a selected parent that is notarized but not yet
    /// materialized, from a private execution of it. A leader uses it only
    /// after its waits; a voter uses it at once.
    read_private_parent: Option<ParentReader>,
    /// View whose parent this leader could not read yet, and how often it asked.
    parent_waits: std::sync::Mutex<(u64, u32)>,
    /// Where this member's reasons for declining and refusing are noted.
    liveness: Option<Arc<Liveness>>,
}

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
            parent_waits: std::sync::Mutex::new((0, 0)),
            liveness: None,
        })
    }

    pub fn with_private_reader(mut self, reader: Option<ParentReader>) -> Self {
        self.read_private_parent = reader;
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

    /// The committed parent, else, when allowed, a private execution of it.
    fn parent_or_private(&self, context: ProposalContext, private: bool) -> std::result::Result<AuthorizedParent, Unauthorized> {
        self.checked_parent(context, &self.read_parent).or_else(|(reason, committed)| {
            let Some(reader) = self.read_private_parent.as_ref().filter(|_| private) else {
                return Err((reason, committed));
            };
            self.checked_parent(context, reader)
                .map_err(|(reason, private)| (reason, format!("{committed}; unfinalized: {private}")))
        })
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
        let waited = {
            let waits = self.parent_waits.lock().unwrap();
            waits.0 == context.view && waits.1 >= PARENT_WAITS
        };
        let parent = match self.parent_or_private(context, waited) {
            Ok(parent) => parent,
            Err((reason, detail)) => {
                self.note(Step::Propose, context, reason, detail);
                let mut waits = self.parent_waits.lock().unwrap();
                *waits = if waits.0 == context.view { (context.view, waits.1 + 1) } else { (context.view, 1) };
                return None;
            }
        };
        *self.parent_waits.lock().unwrap() = (context.view, 0);
        if let Some(request) = parent.closing_request {
            let seal = Seal {
                request,
                session: self.session_id,
                view: context.view,
                checkpoint: parent.checkpoint,
            };
            return Some((digest_from_identity(seal.digest()), seal.encode()));
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
            return None;
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
        let parent = match self.parent_or_private(context, true) {
            Ok(parent) => parent,
            Err((reason, detail)) => {
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
            return valid;
        }
        self.inner.verify_with_context(context, digest, Some(bytes))
    }
}
