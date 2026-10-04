//! Terminal handoff proposals over the ordinary application frame proposer.
//!
//! The parent reader is a trusted application boundary: it must authenticate the
//! globally authorized session/request and return durably materialized DATA
//! state, including outgoing history, for the selected parent. A header's
//! pre-state roots, the latest local clock head, or a seal itself cannot supply
//! that state. Read/sync failures must return an error, never an empty checkpoint.

use std::sync::Arc;

use quil_types::error::Result;

use crate::adapters::{digest_from_identity, Digest, GlobalProposer, ProposalContext};

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
        })
    }

    pub fn with_private_reader(mut self, reader: Option<ParentReader>) -> Self {
        self.read_private_parent = reader;
        self
    }

    fn parent(&self, context: ProposalContext) -> Option<AuthorizedParent> {
        self.checked_parent(context, &self.read_parent)
    }

    /// The committed parent, else, when allowed, a private execution of it.
    fn parent_or_private(&self, context: ProposalContext, private: bool) -> Option<AuthorizedParent> {
        self.parent(context).or_else(|| {
            let reader = self.read_private_parent.as_ref().filter(|_| private)?;
            self.checked_parent(context, reader)
        })
    }

    fn checked_parent(&self, context: ProposalContext, reader: &ParentReader) -> Option<AuthorizedParent> {
        if context.epoch != self.session.generation || context.view <= context.parent_view {
            return None;
        }
        let parent = (reader)(context).ok()?;
        let checkpoint = &parent.checkpoint;
        if checkpoint.view != context.parent_view
            || checkpoint.digest != context.parent.0
            || checkpoint.frame < self.session.base_frame
        {
            return None;
        }
        if checkpoint.frame == self.session.base_frame {
            // Generation zero's base is the registered legacy tip: a certified
            // frame at its own view, not a virtual genesis at view zero.
            let virtual_genesis = self.session.generation != 0;
            if (virtual_genesis && checkpoint.view != 0) || checkpoint.digest != self.session.genesis {
                return None;
            }
        } else if checkpoint.view == 0 {
            return None;
        }
        Some(parent)
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
        let Some(parent) = self.parent_or_private(context, waited) else {
            let mut waits = self.parent_waits.lock().unwrap();
            *waits = if waits.0 == context.view { (context.view, waits.1 + 1) } else { (context.view, 1) };
            return None;
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
            return None;
        }
        Some((digest, bytes))
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
            return false;
        };
        let Some(parent) = self.parent_or_private(context, true) else {
            return false;
        };
        if Seal::is_encoding(&bytes) {
            let Some(request) = parent.closing_request else {
                return false;
            };
            let Ok(seal) = Seal::decode(&bytes) else {
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
            }
            return valid;
        }
        self.inner.verify_with_context(context, digest, Some(bytes))
    }
}
