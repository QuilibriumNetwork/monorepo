//! Generation zero: moving a shard with legacy-certified history into
//! authorized sessions, in place.
//!
//! A legacy shard is certified by the registry committee at each frame's GLOBAL
//! anchor, in Simplex epoch 0 and the `appshard‖filter` namespace. That is
//! exactly the namespace a generation-0 session signs in, so a legacy committee
//! can finalize a terminal seal that GLOBAL verifies as a generation-0 source,
//! and the ordinary successor machinery then activates generation 1 from the
//! checkpoint the committee itself agreed on. Generation zero is therefore a
//! closing-only record: registered and scheduled into its successor in the same
//! GLOBAL frame, never re-scheduled.
//!
//! Every step is GLOBAL state committed with the GLOBAL cursor, so the
//! migration's progress markers are the records themselves: a replayed or
//! restarted frame recomputes the same outcome, and a shard registered in an
//! earlier frame is never registered again.
//!
//! 1. **Legacy tip.** From [`LEGACY_TIP_LEAD`] frames before the policy's
//!    activation, each legacy-verified header GLOBAL executes records its
//!    shard's highest executed frame and that frame's anchor. A shard with a tip
//!    and no session is *pending*: it keeps the legacy verifier and never
//!    receives an empty-genesis first session.
//! 2. **Registration** (maintenance pass, from activation): a pending shard
//!    whose tip was certified in the current storage epoch — so the registry
//!    committee that certified it is the committee registered — receives a
//!    generation-0 session at its tip, and a request for its generation-1
//!    successor with the same eligible members.
//! 3. **Seal and activation** are the ordinary handoff: the legacy committee
//!    seals its materialized head; GLOBAL accepts the seal once it has executed
//!    the shard through the sealed checkpoint, and authorizes generation 1.
//!
//! Frames at or below a generation-0 source's base (its legacy tip) are legacy
//! history and keep the legacy verifier forever; frames above it verify against
//! the registered members.
use quil_cw_consensus::handoff::{Checkpoint, Cursor, Session};
use quil_types::consensus::{CommitteeHandoffPolicy, LegacyHistory};
use quil_types::error::{QuilError, Result};
use sha2::{Digest as _, Sha256};

use super::schedule::{desired_members, reserve, reserved};
use super::{atomic, create_session, head, invalid, read, record_member_rings, record_session_tip, schedule, set_status, write, DesiredCommittee, Records};
use crate::hypergraph_state::HypergraphState;
use crate::prover_registry::CommittedProverScan;

/// The generation-zero migration choices, each at the default this code
/// implements. All are consensus-affecting, so each is a constant every
/// node compiles in, never a per-node flag; changing one is a
/// coordinated release. An alternative that is not implemented fails the
/// build if selected here, rather than silently running the default.
pub mod defaults {
    /// Frames before activation from which legacy tips are recorded: one
    /// storage epoch, so every live legacy shard has a tip when registration
    /// starts. The activation frame and chain id themselves are the installed
    /// `CommitteeHandoffPolicy` (`init_committee_handoff_for_network`); mainnet
    /// installs none.
    pub const LEGACY_TIP_LEAD: u64 = quil_types::consensus::EPOCH_LENGTH_FRAMES;

    /// A legacy shard with no header executed in the lead window has no
    /// tip, and gets an empty-genesis first session like any unmanaged shard
    /// (the pre-existing rule). Holding it pending or a census at activation
    /// would need the set of legacy filters recorded at `A`.
    pub const DEAD_LEGACY_SHARDS_GET_A_FRESH_SESSION: bool = true;

    /// Generation 1 is scheduled at registration with the same eligible
    /// members as generation 0. Deferring the choice to a later
    /// reconciliation pass is not implemented.
    pub const GENERATION_ONE_KEEPS_THE_ELIGIBLE_SET: bool = true;

    /// A tip certified in an earlier storage epoch than the registering
    /// frame waits for a current-epoch tip (the pending shard keeps
    /// producing). Registering it anyway would also need an engine that can
    /// resume from a head certified by a committee other than generation 0's.
    pub const WAIT_FOR_A_CURRENT_EPOCH_TIP: bool = true;

    /// Legacy history (at or below a generation-0 base) keeps the legacy
    /// verifier for this many storage epochs after generation 1 activates;
    /// `None` is forever, as today. A sunset is not implemented.
    pub const LEGACY_VERIFIER_SUNSET_EPOCHS: Option<u64> = None;

    // Heads still carrying a legacy aggregate signature are not handled
    // here: `--gen0-preflight` reports each one as a blocker; such a shard
    // cannot seal until it finalizes a Simplex frame.

    const _: () = assert!(DEAD_LEGACY_SHARDS_GET_A_FRESH_SESSION, "D2 alternatives are not implemented");
    const _: () = assert!(GENERATION_ONE_KEEPS_THE_ELIGIBLE_SET, "D3 alternative is not implemented");
    const _: () = assert!(WAIT_FOR_A_CURRENT_EPOCH_TIP, "D4 alternative is not implemented");
    const _: () = assert!(LEGACY_VERIFIER_SUNSET_EPOCHS.is_none(), "D5 sunset is not implemented");
}

pub use defaults::LEGACY_TIP_LEAD;

/// Generation-0 registrations per maintenance pass; the rest continue in later
/// passes. Each carries its members' Falcon keys (about 0.9 KB each) twice:
/// in the session and in its successor request.
pub const MAX_REGISTRATIONS_PER_PASS: usize = 64;

/// The highest legacy-verified frame GLOBAL executed for a shard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyTip {
    /// Coordinates and state roots from the certified header. The history root
    /// is not in a header and is zero.
    pub checkpoint: Checkpoint,
    /// The header's GLOBAL anchor: its certifying committee is the registry's
    /// at this frame.
    pub anchor: u64,
}

impl LegacyTip {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.checkpoint.write(&mut bytes);
        bytes.extend_from_slice(&self.anchor.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes)?;
        let checkpoint = Checkpoint::read(&mut cursor)?;
        let anchor = cursor.u64()?;
        cursor.finish()?;
        Ok(Self { checkpoint, anchor })
    }
}

/// A registered generation-0 source: the GLOBAL frame that registered it and
/// the legacy tip it continues from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacySource {
    pub registered_at: u64,
    pub tip: LegacyTip,
}

/// Whether legacy tips are recorded for headers executed at `frame`. Never
/// under a flag day ([`LegacyHistory::Discard`]): no shard is pending, so
/// every shard receives a first session at frame 0.
pub fn records_tips(policy: &CommitteeHandoffPolicy, frame: u64) -> bool {
    policy.legacy_history == LegacyHistory::Migrate
        && frame >= policy.activation_frame.saturating_sub(LEGACY_TIP_LEAD)
}

pub fn tip(state: &impl Records, filter: &[u8]) -> Result<Option<LegacyTip>> {
    read(state, b"legacy-tip", filter)?.map(|bytes| LegacyTip::decode(&bytes)).transpose()
}

/// Advance `filter`'s legacy tip to `tip` if it is higher. Called for headers
/// the legacy verifier accepted; a shard already in the protocol has a session
/// and keeps its tip where registration found it.
pub fn record_tip(state: &HypergraphState, frame: u64, filter: &[u8], tip: &LegacyTip) -> Result<()> {
    if head(state, filter)?.is_some() {
        return Ok(());
    }
    if self::tip(state, filter)?.is_some_and(|current| current.checkpoint.frame >= tip.checkpoint.frame) {
        return Ok(());
    }
    write(state, frame, b"legacy-tip", filter, &tip.encode())
}

/// A shard with executed legacy history and no session yet: it keeps the
/// legacy verifier until its generation-0 source is registered.
pub fn pending(state: &impl Records, filter: &[u8]) -> Result<bool> {
    Ok(head(state, filter)?.is_none() && tip(state, filter)?.is_some())
}

pub fn source(state: &impl Records, id: &[u8; 32]) -> Result<Option<LegacySource>> {
    read(state, b"legacy-source", id)?
        .map(|bytes| {
            let (at, rest) = bytes
                .split_first_chunk::<8>()
                .ok_or_else(|| QuilError::Store("corrupt legacy source record".into()))?;
            Ok(LegacySource { registered_at: u64::from_be_bytes(*at), tip: LegacyTip::decode(rest)? })
        })
        .transpose()
}

/// Whether a frame of `filter` is legacy history: at or below its
/// generation-0 source's base, or on a shard still pending registration.
/// Such frames keep the legacy verifier (the registry committee at the frame's
/// anchor) even once the application is managed.
pub fn is_legacy_history(state: &impl Records, filter: &[u8], frame: u64) -> Result<bool> {
    // No sunset; legacy history keeps its verifier.
    if let Some(zero) = super::session_at_generation(state, filter, 0)? {
        return Ok(frame <= zero.base_frame);
    }
    pending(state, filter)
}

/// Register `filter`'s generation-0 source at its legacy tip. The session
/// continues the legacy namespace, so its members must be the committee that
/// certifies the shard now; its genesis is the tip's identity and its base the
/// tip's frame. Only [`migrate`] calls this.
fn register_source(
    state: &HypergraphState,
    frame: u64,
    policy: &CommitteeHandoffPolicy,
    filter: &[u8],
    members: Vec<Vec<u8>>,
    tip: &LegacyTip,
) -> Result<Session> {
    let mut hash = Sha256::new();
    hash.update(b"quil/app/handoff/legacy-source/v1");
    hash.update(frame.to_be_bytes());
    hash.update(tip.encode());
    let session = Session {
        chain_id: policy.chain_id,
        filter: filter.to_vec(),
        generation: 0,
        genesis: tip.checkpoint.digest,
        base_frame: tip.checkpoint.frame,
        authorization: hash.finalize().into(),
        members,
    };
    session.validate()?;
    let id = create_session(state, frame, &session)?;
    // A source without origins: nothing seals into generation zero.
    write(state, frame, b"origin", &id, &[])?;
    set_status(state, frame, &id, 0, None)?;
    record_member_rings(state, frame, &id, &session, &[], false)?;
    let mut record = frame.to_be_bytes().to_vec();
    record.extend_from_slice(&tip.encode());
    write(state, frame, b"legacy-source", &id, &record)?;
    // GLOBAL has executed the shard through its tip, so a seal of the tip
    // itself (a committee with nothing after it) is acceptable at once.
    record_session_tip(state, frame, &id, &tip.checkpoint)?;
    Ok(session)
}

/// One migration pass over the registered shard grid (`filters`): register
/// generation-0 sources for pending shards and schedule each into its
/// generation-1 successor. Returns how many were registered.
///
/// A pending shard waits while its tip's anchor is in an earlier storage epoch
/// than `frame` (its certifying committee may differ from the eligible set) or
/// while it has no eligible members.
pub fn migrate(
    state: &HypergraphState,
    frame: u64,
    policy: &CommitteeHandoffPolicy,
    filters: &[Vec<u8>],
    scan: &CommittedProverScan,
) -> Result<usize> {
    if frame < policy.activation_frame || policy.legacy_history != LegacyHistory::Migrate {
        return Ok(0);
    }
    let epoch = quil_types::consensus::epoch_for_frame(frame);
    let mut registered = 0;
    for filter in filters {
        if registered >= MAX_REGISTRATIONS_PER_PASS {
            break;
        }
        if head(state, filter)?.is_some() || reserved(state, filter)? {
            continue;
        }
        let Some(tip) = tip(state, filter)? else { continue };
        // Wait for a tip its current committee certified.
        if defaults::WAIT_FOR_A_CURRENT_EPOCH_TIP && quil_types::consensus::epoch_for_frame(tip.anchor) != epoch {
            continue;
        }
        let members = desired_members(scan, filter, frame);
        if members.is_empty() {
            continue;
        }
        atomic(state, || {
            let source = register_source(state, frame, policy, filter, members.clone(), &tip)?;
            // Generation 1 keeps the eligible set.
            let targets = vec![DesiredCommittee { filter: filter.clone(), members }];
            let request = schedule(state, frame, vec![filter.clone()], targets.clone())?;
            reserve(state, frame, &targets, &request.id()?)?;
            tracing::info!(
                frame,
                filter = hex::encode(filter),
                base_frame = source.base_frame,
                request = hex::encode(request.id()?),
                "committee handoff: legacy shard registered as generation zero and scheduled into its successor"
            );
            Ok(())
        })?;
        registered += 1;
    }
    Ok(registered)
}

/// Refuse a generation-0 session anywhere but [`register_source`].
pub(super) fn refuse_unaudited_generation_zero(session: &Session) -> Result<()> {
    if session.generation == 0 {
        return Err(invalid("generation zero is only registered from a legacy tip"));
    }
    Ok(())
}
