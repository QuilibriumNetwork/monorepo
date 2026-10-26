//! Seniority succession, and the seniority-merge rules that activate with it
//! ([`quil_types::consensus::seniority_succession_active`]).
//!
//! A `ProverSeniorityMerge` names Ed448 node keys (its targets). Each target
//! has up to two spent markers, written by the join or the seniority merge
//! that consumed it, and each marker names the prover it credited. From the
//! activation epoch the targets' committed markers select what the op does:
//!
//! - every target unconsumed or credited to the submitting prover: a merge.
//!   It must name at least one unconsumed target and raise the prover's
//!   seniority; keys already counting for the prover add nothing. A replay
//!   names no unconsumed target and is refused.
//! - some targets credited to one other prover X, the rest (if any) to the
//!   submitter: a succession. Their owner moves what those keys brought X
//!   to the submitting prover Y, once X is idle and quiet
//!   ([`succession_amounts`]): the keys' retro X still holds, and X's
//!   accrual (its seniority beyond retro) pro rata to that retro's share of
//!   X's retro, or all of it to the first mover from an X with no ledger.
//!   Y's gain drops Y's own accrual overlapping X's activity
//!   (`A_Y − 10·(F − X_end)`) and retro Y already holds; it never exceeds
//!   what X loses. The moved keys' markers then name Y; X's other keys stay
//!   X's. Accrual X earns after a succession stays with X, except the share
//!   later moves of its remaining keys take.
//!
//! Retro seniority counts once per prover. From the activation epoch every
//! prover keeps a retro ledger per part of
//! [`crate::seniority_compat::retro_components`]: what it holds
//! (`RetroCredited`) and what successions moved out of it (`RetroMoved`). A
//! merge, join or succession credits only what raises a held part
//! ([`credit_retro`]), however keys are split across ops. A prover credited
//! before activation starts its ledger from the own keys its first op names:
//! any later op can fully credit a fresh key overlapping a pre-activation
//! own key it never named, so each part can leak once, bounded by the
//! prover's pre-activation retro.
//!
//! Keys whose markers fit nothing (a legacy marker naming no prover, or
//! markers crediting two provers) are skipped everywhere, never an error.
//!
//! Validation and materialization both call [`plan_seniority_merge`], so
//! they decide alike over the same state. Before the activation epoch it
//! returns `None` and the earlier rules apply unchanged. The node and the
//! qclient dry run choose what to submit with [`plan_submissions`].

use std::collections::HashMap;

use quil_tries::VectorCommitmentTree;
use quil_types::consensus::{
    seniority_succession_active, seniority_succession_epoch, seniority_succession_quiet_frames,
    EffectiveStatus, ProverAllocationInfo,
};
use quil_types::crypto::KeyManager;
use quil_types::error::{QuilError, Result};

use super::materialize::{
    allocation_address, create_spent_merge_tree, hyperedge_allocation_addresses, kick_bars_rejoin,
    spent_join_merge_address, spent_seniority_merge_address,
};
use super::prover_ops::ProverSeniorityMerge;
use super::prover_shard_update::SENIORITY_PER_ACTIVE_FRAME;
use super::verify::{
    seniority_merge_signer, verify_seniority_merge_consents, verify_seniority_merge_prover_signature,
    SeniorityMergeConsent,
};
use crate::global_schema::{read_field, write_field, GLOBAL_INTRINSIC_ADDRESS};
use crate::hypergraph_state::{hyperedge_adds_discriminator, vertex_adds_discriminator, HypergraphState};
use crate::prover_registry::{decode_allocation_tree, rebuild_vertex_tree_from_blob, vertex_tree_to_blob};

/// Domain of a target's consent to a succession.
pub const SUCCESSION_DOMAIN: &[u8] = b"PROVER_SENIORITY_SUCCESSION";

const PROVER: &str = "prover:Prover";

/// What a target signs to move what it brought the prover at `predecessor`
/// to the prover with `successor_public_key`, in the op of `frame_number`:
/// the key, the address, then the frame (big-endian), so a consent cannot be
/// replayed outside the op's 10-frame window.
pub fn succession_consent_message(
    successor_public_key: &[u8],
    predecessor: &[u8; 32],
    frame_number: u64,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(successor_public_key.len() + predecessor.len() + 8);
    message.extend_from_slice(successor_public_key);
    message.extend_from_slice(predecessor);
    message.extend_from_slice(&frame_number.to_be_bytes());
    message
}

fn refused(reason: impl std::fmt::Display) -> QuilError {
    QuilError::InvalidArgument(format!("prover seniority merge: {reason}"))
}

/// Read access to GLOBAL state: committed, staged, or read ahead.
pub trait GlobalReader {
    /// The vertex at `address` in the GLOBAL domain; `None` when absent.
    fn vertex(&self, address: &[u8; 32]) -> Result<Option<Vec<u8>>>;
    /// The hyperedge at `address` in the GLOBAL domain; `None` when absent.
    fn hyperedge(&self, address: &[u8; 32]) -> Result<Option<Vec<u8>>>;
}

impl GlobalReader for HypergraphState {
    fn vertex(&self, address: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let disc = vertex_adds_discriminator()?;
        Ok(self.get(&GLOBAL_INTRINSIC_ADDRESS[..], address, &disc)?.filter(|blob| !blob.is_empty()))
    }

    fn hyperedge(&self, address: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let disc = hyperedge_adds_discriminator()?;
        Ok(self.get(&GLOBAL_INTRINSIC_ADDRESS[..], address, &disc)?.filter(|blob| !blob.is_empty()))
    }
}

/// GLOBAL vertices and hyperedges read ahead (a client fetches them over
/// RPC), by 32-byte address.
#[derive(Debug, Default, Clone)]
pub struct GlobalSnapshot {
    pub vertices: HashMap<[u8; 32], Vec<u8>>,
    pub hyperedges: HashMap<[u8; 32], Vec<u8>>,
}

impl GlobalReader for GlobalSnapshot {
    fn vertex(&self, address: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self.vertices.get(address).filter(|blob| !blob.is_empty()).cloned())
    }

    fn hyperedge(&self, address: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self.hyperedges.get(address).filter(|blob| !blob.is_empty()).cloned())
    }
}

/// A `prover:Prover` u64 field of `tree`; 0 when absent.
pub fn prover_u64(tree: &VectorCommitmentTree, field: &str) -> u64 {
    read_field(tree, PROVER, field)
        .filter(|bytes| bytes.len() == 8)
        .map(|bytes| u64::from_be_bytes(bytes.try_into().unwrap_or_default()))
        .unwrap_or(0)
}

/// Whom a spent marker credits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerOwner {
    /// A marker that names no prover, written before markers recorded one.
    Unattributed,
    /// The prover the marker credits.
    Prover([u8; 32]),
}

impl MarkerOwner {
    fn of(blob: &[u8]) -> Self {
        let tree = rebuild_vertex_tree_from_blob(blob);
        match read_field(&tree, "merge:SpentMerge", "ProverAddress") {
            Some(address) if address.len() == 32 => {
                Self::Prover(address.try_into().unwrap_or_default())
            }
            _ => Self::Unattributed,
        }
    }
}

/// The committed spent markers of one target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TargetMarkers {
    /// Written by a join that named the target (`PROVER_JOIN_MERGE`).
    pub join: Option<MarkerOwner>,
    /// Written by a seniority merge that named it (`PROVER_SENIORITY_MERGE`).
    pub seniority: Option<MarkerOwner>,
}

impl TargetMarkers {
    /// The markers of the target with Ed448 key `target_public_key`.
    pub fn read(reader: &dyn GlobalReader, target_public_key: &[u8]) -> Result<Self> {
        let owner = |address: [u8; 32]| -> Result<Option<MarkerOwner>> {
            Ok(reader.vertex(&address)?.map(|blob| MarkerOwner::of(&blob)))
        };
        Ok(Self {
            join: owner(spent_join_merge_address(target_public_key)?)?,
            seniority: owner(spent_seniority_merge_address(target_public_key)?)?,
        })
    }

    /// No join or merge consumed the target.
    pub fn is_empty(&self) -> bool {
        self.join.is_none() && self.seniority.is_none()
    }

    fn owners(&self) -> impl Iterator<Item = MarkerOwner> + '_ {
        self.join.iter().chain(self.seniority.iter()).copied()
    }

    /// Where the target stands for a merge by `submitter`.
    pub fn standing(&self, submitter: &[u8; 32]) -> TargetStanding {
        let mut other: Option<[u8; 32]> = None;
        let mut own = false;
        for owner in self.owners() {
            match owner {
                MarkerOwner::Unattributed => return TargetStanding::Unusable(Unusable::Legacy),
                MarkerOwner::Prover(address) if address == *submitter => own = true,
                MarkerOwner::Prover(address) => match other {
                    None => other = Some(address),
                    Some(seen) if seen == address => {}
                    Some(_) => return TargetStanding::Unusable(Unusable::Conflicting),
                },
            }
        }
        match (other, own) {
            (None, false) => TargetStanding::Fresh,
            (None, true) => TargetStanding::Own,
            (Some(prover), false) => TargetStanding::Other(prover),
            (Some(_), true) => TargetStanding::Unusable(Unusable::Conflicting),
        }
    }
}

/// Why a target fits no merge or succession.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unusable {
    /// A marker names no prover (written before markers recorded one), so
    /// nothing shows whose seniority it holds.
    Legacy,
    /// Its markers credit different provers.
    Conflicting,
}

impl std::fmt::Display for Unusable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Legacy => write!(f, "a spent marker names no prover (a legacy marker)"),
            Self::Conflicting => write!(f, "its spent markers credit different provers"),
        }
    }
}

/// Where a target stands for a merge by one prover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetStanding {
    /// No join or merge consumed it: a merge credits it.
    Fresh,
    /// It already counts for the submitting prover: an op may name it, and it
    /// adds nothing.
    Own,
    /// It counts for another prover: a succession may move what it brought
    /// that prover.
    Other([u8; 32]),
    /// It fits no merge or succession.
    Unusable(Unusable),
}

/// What a `ProverSeniorityMerge` does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeniorityMergeMode {
    /// Before the activation epoch: the rules this build had before.
    Legacy,
    /// Credit the unconsumed targets' retro seniority to the submitting
    /// prover.
    Merge,
    /// Move what the targets counting for the prover at `predecessor`
    /// brought it to the submitting prover.
    Succession { predecessor: [u8; 32] },
}

/// The mode of a merge by `submitter` whose targets have `markers`, at GLOBAL
/// frame `frame`. Refuses markers that fit no mode.
pub fn select_mode(frame: u64, submitter: &[u8; 32], markers: &[TargetMarkers]) -> Result<SeniorityMergeMode> {
    if !seniority_succession_active(frame) {
        return Ok(SeniorityMergeMode::Legacy);
    }
    mode_from_markers(submitter, markers)
}

/// [`select_mode`] once succession is active: targets that are unconsumed
/// or count for the submitter make a merge; targets counting for one other
/// prover, with any counting for the submitter, make a succession. Targets
/// whose markers fit nothing are skipped. Refused: targets counting for two
/// other provers, or an unconsumed target in a succession (it would be
/// consumed without credit).
pub fn mode_from_markers(submitter: &[u8; 32], markers: &[TargetMarkers]) -> Result<SeniorityMergeMode> {
    let mut predecessor: Option<[u8; 32]> = None;
    let mut fresh = false;
    for target in markers {
        match target.standing(submitter) {
            TargetStanding::Unusable(_) | TargetStanding::Own => {}
            TargetStanding::Fresh => fresh = true,
            TargetStanding::Other(prover) => match predecessor {
                None => predecessor = Some(prover),
                Some(seen) if seen == prover => {}
                Some(_) => return Err(refused("the targets count for different provers")),
            },
        }
    }
    match predecessor {
        None => Ok(SeniorityMergeMode::Merge),
        Some(_) if fresh => Err(refused(
            "a succession names an unconsumed target; merge it separately",
        )),
        Some(predecessor) => Ok(SeniorityMergeMode::Succession { predecessor }),
    }
}

/// The predecessor of a succession as committed state shows it.
#[derive(Debug, Clone)]
pub struct PredecessorState {
    pub address: [u8; 32],
    pub public_key: Vec<u8>,
    pub seniority: u64,
    pub kick_frame_number: u64,
    pub last_seniority_frame_number: u64,
    /// Its retro ledger: the retro it holds and the retro moved out of it.
    pub retro: ProverRetro,
    /// Every allocation its hyperedge links, and its global allocation.
    pub allocations: Vec<ProverAllocationInfo>,
}

/// Every frame field of an allocation.
pub fn allocation_frames(allocation: &ProverAllocationInfo) -> [u64; 11] {
    [
        allocation.join_frame_number,
        allocation.leave_frame_number,
        allocation.pause_frame_number,
        allocation.resume_frame_number,
        allocation.kick_frame_number,
        allocation.join_confirm_frame_number,
        allocation.join_reject_frame_number,
        allocation.leave_confirm_frame_number,
        allocation.leave_reject_frame_number,
        allocation.last_active_frame_number,
        allocation.last_signed_frame_number,
    ]
}

impl PredecessorState {
    /// The prover at `address` and its allocations; `None` without a prover
    /// vertex carrying a public key.
    pub fn read(reader: &dyn GlobalReader, address: &[u8; 32]) -> Result<Option<Self>> {
        let Some(blob) = reader.vertex(address)? else {
            return Ok(None);
        };
        let tree = rebuild_vertex_tree_from_blob(&blob);
        let public_key = read_field(&tree, PROVER, "PublicKey").unwrap_or_default();
        if public_key.is_empty() {
            return Ok(None);
        }
        let mut linked = hyperedge_allocation_addresses(&reader.hyperedge(address)?.unwrap_or_default())?;
        let global = allocation_address(&public_key, &[])?;
        if !linked.contains(&global) {
            linked.push(global);
        }
        let mut allocations = Vec::with_capacity(linked.len());
        for allocation in &linked {
            let Some(blob) = reader.vertex(allocation)? else {
                continue;
            };
            let tree = rebuild_vertex_tree_from_blob(&blob);
            if let Some((owner, info)) = decode_allocation_tree(allocation, &tree) {
                if owner.as_slice() == address.as_slice() {
                    allocations.push(info);
                }
            }
        }
        Ok(Some(Self {
            address: *address,
            seniority: prover_u64(&tree, "Seniority"),
            kick_frame_number: prover_u64(&tree, "KickFrameNumber"),
            last_seniority_frame_number: prover_u64(&tree, "LastSeniorityFrameNumber"),
            retro: ProverRetro::of(&tree),
            public_key,
            allocations,
        }))
    }

    /// The last frame with recorded activity: its `LastSeniorityFrameNumber`
    /// and every frame field of every allocation. A rejoin clears the prover
    /// field; the allocations' fields still record the activity.
    pub fn end_frame(&self) -> u64 {
        self.allocations
            .iter()
            .flat_map(allocation_frames)
            .fold(self.last_seniority_frame_number, u64::max)
    }

    /// The last activity recorded for `allocation`: its frame fields and the
    /// prover's `LastSeniorityFrameNumber`.
    pub fn allocation_end_frame(&self, allocation: &ProverAllocationInfo) -> u64 {
        allocation_frames(allocation).into_iter().fold(self.last_seniority_frame_number, u64::max)
    }

    /// The effective status of `allocation` when it keeps this prover from
    /// being succeeded at `frame`: a live allocation with recorded activity
    /// within the quiet period, or an Active global allocation, which
    /// records no activity while its prover produces GLOBAL frames. A
    /// Paused or other live allocation without activity for the quiet period
    /// is left behind and counts as idle.
    pub fn allocation_blocks(&self, allocation: &ProverAllocationInfo, frame: u64) -> Option<EffectiveStatus> {
        let status = allocation.effective_status(frame);
        let recent =
            frame.saturating_sub(self.allocation_end_frame(allocation)) < seniority_succession_quiet_frames();
        let global = allocation.confirmation_filter.is_empty() && status == EffectiveStatus::Active;
        (status.is_live() && (recent || global)).then_some(status)
    }

    /// The frame its first recorded allocation joined, if any.
    pub fn start_frame(&self) -> Option<u64> {
        self.allocations.iter().map(|allocation| allocation.join_frame_number).filter(|&frame| frame > 0).min()
    }
}


/// What keeps a succession from applying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessionBlocker {
    /// The network has not reached the activation epoch (`u64::MAX`: none).
    Inactive { epoch: u64 },
    /// The markers name the submitting prover itself.
    SameProver,
    /// No prover vertex at the address the markers name.
    PredecessorMissing,
    /// The predecessor's kick still bars it.
    PredecessorKicked { frame: u64 },
    /// The submitting prover's kick still bars it.
    SuccessorKicked { frame: u64 },
    /// The predecessor holds no seniority.
    NoSeniority,
    /// An allocation of the predecessor is live and recorded activity
    /// within the quiet period. A live allocation with no activity for the
    /// quiet period (a Paused or global allocation left behind) is idle.
    Live { filter: Vec<u8>, status: EffectiveStatus },
    /// The predecessor's last activity is within the quiet period.
    Quiet { remaining: u64, until: u64 },
    /// The keys would not raise the submitting prover's seniority: they are
    /// worth nothing, or their retro already counts for it.
    NoGain,
}

impl std::fmt::Display for SuccessionBlocker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inactive { epoch: u64::MAX } => {
                write!(f, "seniority succession is not active on this network (no activation epoch is set)")
            }
            Self::Inactive { epoch } => write!(f, "seniority succession activates at epoch {epoch}"),
            Self::SameProver => write!(f, "the markers already name this prover"),
            Self::PredecessorMissing => write!(f, "the prover the markers name has no prover record"),
            Self::PredecessorKicked { frame } => write!(f, "the predecessor was kicked at frame {frame}"),
            Self::SuccessorKicked { frame } => write!(f, "this prover was kicked at frame {frame}"),
            Self::NoSeniority => write!(f, "the predecessor holds no seniority"),
            Self::Live { filter, status } if filter.is_empty() => {
                write!(f, "the predecessor's global allocation is {status:?}")
            }
            Self::Live { filter, status } => {
                write!(f, "the predecessor's allocation on shard {} is {status:?}", hex::encode(filter))
            }
            Self::Quiet { remaining, until } => write!(
                f,
                "the predecessor was active too recently: {remaining} more frames without activity (until frame {until})"
            ),
            Self::NoGain => write!(f, "the keys would not raise this prover's seniority"),
        }
    }
}

/// Retro seniority by part of [`crate::seniority_compat::retro_components`]:
/// the four retro epochs, then the mainnet snapshot.
pub type RetroParts = [u64; 5];

/// The seniority `parts` are worth.
pub fn retro_value(parts: &RetroParts) -> u64 {
    crate::seniority_compat::aggregate_retro_components(parts)
}

fn parts_max(a: &RetroParts, b: &RetroParts) -> RetroParts {
    std::array::from_fn(|index| a[index].max(b[index]))
}

/// The retro parts recorded as credited to the prover with vertex `tree`
/// (`RetroCredited`); `None` before its first op under the succession rules.
pub fn credited_retro(tree: &VectorCommitmentTree) -> Option<RetroParts> {
    read_parts(tree, "RetroCredited")
}

/// Record `parts` as the retro credited to the prover with vertex `tree`.
pub fn set_credited_retro(tree: &mut VectorCommitmentTree, parts: &RetroParts) -> Result<()> {
    let bytes: Vec<u8> = parts.iter().flat_map(|part| part.to_be_bytes()).collect();
    write_field(tree, PROVER, "RetroCredited", &bytes)
}

fn read_parts(tree: &VectorCommitmentTree, field: &str) -> Option<RetroParts> {
    let bytes = read_field(tree, PROVER, field).filter(|bytes| bytes.len() == 40)?;
    Some(std::array::from_fn(|index| {
        u64::from_be_bytes(bytes[index * 8..index * 8 + 8].try_into().unwrap_or_default())
    }))
}

fn write_parts(tree: &mut VectorCommitmentTree, field: &str, parts: &RetroParts) -> Result<()> {
    let bytes: Vec<u8> = parts.iter().flat_map(|part| part.to_be_bytes()).collect();
    write_field(tree, PROVER, field, &bytes)
}

/// A prover's seniority and retro ledger: the retro it holds
/// (`RetroCredited`) and the retro successions moved out of it
/// (`RetroMoved`), per part. Neither is recorded before its first op under
/// the succession rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProverRetro {
    pub seniority: u64,
    pub held: Option<RetroParts>,
    pub moved: Option<RetroParts>,
}

impl ProverRetro {
    pub fn of(tree: &VectorCommitmentTree) -> Self {
        Self {
            seniority: prover_u64(tree, "Seniority"),
            held: credited_retro(tree),
            moved: read_parts(tree, "RetroMoved"),
        }
    }

    /// Any ledger recorded.
    pub fn recorded(&self) -> bool {
        self.held.is_some() || self.moved.is_some()
    }

    /// Write `held`, `moved` and `seniority` on the prover vertex `tree`.
    pub fn write(&self, tree: &mut VectorCommitmentTree) -> Result<()> {
        write_field(tree, PROVER, "Seniority", &self.seniority.to_be_bytes())?;
        if let Some(held) = &self.held {
            set_credited_retro(tree, held)?;
        }
        if let Some(moved) = &self.moved {
            write_parts(tree, "RetroMoved", moved)?;
        }
        Ok(())
    }
}

/// What crediting `added` keys gives a prover that records `credited` (and
/// `moved` out), and whose keys `own` (named with them) already count for
/// it: the seniority they add, and the parts to record. Only parts the added keys raise count,
/// so a key, or another key of an overlapping period, counts once however
/// keys are split across ops. Without a record the prover starts from its
/// named own keys.
pub fn credit_retro(
    credited: Option<RetroParts>,
    moved: Option<RetroParts>,
    added: &[Vec<u8>],
    own: &[Vec<u8>],
    retro: &dyn Fn(&[Vec<u8>]) -> RetroParts,
) -> (u64, RetroParts) {
    let base = held_base(credited, moved, own, retro);
    let after = parts_max(&base, &retro(added));
    (retro_value(&after).saturating_sub(retro_value(&base)), after)
}

/// What a prover holds before crediting new keys: its held ledger, and the
/// parts of its named own keys, less what successions moved out of it (an
/// own key whose period moved out holds nothing there any more).
fn held_base(
    held: Option<RetroParts>,
    moved: Option<RetroParts>,
    own: &[Vec<u8>],
    retro: &dyn Fn(&[Vec<u8>]) -> RetroParts,
) -> RetroParts {
    let held = held.unwrap_or_default();
    let moved = moved.unwrap_or_default();
    let own = retro(own);
    std::array::from_fn(|p| held[p].max(own[p].saturating_sub(moved[p])))
}

/// What a succession moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SuccessionAmounts {
    /// The predecessor loses this: the moved keys' retro it still holds, and
    /// its accrual share, never more than it holds.
    pub debit: u64,
    /// Of `debit`, the predecessor's accrual.
    pub accrual: u64,
    /// The successor gains this: what the moved retro raises in its ledger,
    /// and the moved accrual less the successor's own accrual that overlaps
    /// the predecessor's activity. Never more than `debit`, so no seniority
    /// is created: when the moved retro already counts for the successor,
    /// the predecessor still loses it.
    pub credit: u64,
    /// The predecessor's ledger and seniority after the succession.
    pub predecessor: ProverRetro,
    /// The successor's ledger and seniority after the succession.
    pub successor: ProverRetro,
}

/// The amounts of a succession at `frame` that moves the keys `moved` from
/// `predecessor` (last active at `end_frame`) to `successor` (first active
/// at `successor_start`, if known), whose keys `own` are named too.
///
/// Retro: a part the predecessor holds, or a key's part beyond what has
/// moved out of it (its marker proves the predecessor was credited it),
/// moves once. The predecessor's ledger drops what moved and records it as
/// moved out, so two keys of one period are debited once, a later mover
/// still finds its own keys, and a successor that moves keys back is
/// credited them again. Two movers of keys of one period: the first takes
/// the period (order-dependent, by design). On the successor's side an own
/// key holds nothing in a period that moved out of it ([`credit_retro`]),
/// and a credit capped below the moved retro (the predecessor held less)
/// leaves the successor holding that retro in proportion, the rest recorded
/// as moved out.
///
/// Accrual (seniority beyond retro): a predecessor with a ledger gives each
/// mover its accrual pro rata to the moved retro's share of the retro it
/// holds. A predecessor without one (credited only before the succession
/// epoch, so its retro total is unknown) gives its whole accrual to the
/// first mover, and from then on has a ledger: later movers of its other
/// keys take their keys' retro, from what it still holds.
///
/// The successor's accrual earned before the predecessor stopped (beyond
/// `SENIORITY_PER_ACTIVE_FRAME` per frame since then) is taken off the
/// moved accrual, so the same node's time counts once; none is when the
/// successor started after the predecessor stopped.
#[allow(clippy::too_many_arguments)]
pub fn succession_amounts(
    predecessor: &ProverRetro,
    successor: &ProverRetro,
    successor_start: Option<u64>,
    moved: &[Vec<u8>],
    own: &[Vec<u8>],
    frame: u64,
    end_frame: u64,
    retro: &dyn Fn(&[Vec<u8>]) -> RetroParts,
) -> SuccessionAmounts {
    let keys = retro(moved);
    let held = predecessor.held.unwrap_or_default();
    let out = predecessor.moved.unwrap_or_default();
    let available: RetroParts = std::array::from_fn(|p| held[p].max(keys[p].saturating_sub(out[p])));
    let taken: RetroParts = std::array::from_fn(|p| keys[p].min(available[p]));
    let left: RetroParts = std::array::from_fn(|p| available[p] - taken[p]);
    let retro_debit = retro_value(&available).saturating_sub(retro_value(&left));
    let accrual_share = if predecessor.recorded() {
        let total = retro_value(&available);
        if total == 0 {
            0
        } else {
            let accrual = predecessor.seniority.saturating_sub(total);
            (u128::from(accrual) * u128::from(retro_debit) / u128::from(total)) as u64
        }
    } else {
        predecessor.seniority.saturating_sub(retro_debit)
    };
    let debit = predecessor.seniority.min(retro_debit.saturating_add(accrual_share));
    let accrual = debit - retro_debit.min(debit);

    let successor_out = successor.moved.unwrap_or_default();
    let base = held_base(successor.held, successor.moved, own, retro);
    let after = parts_max(&base, &taken);
    let retro_credit = retro_value(&after).saturating_sub(retro_value(&base));
    let successor_accrual = successor.seniority.saturating_sub(retro_value(&base));
    let overlap = match successor_start {
        Some(start) if start >= end_frame => 0,
        _ => successor_accrual.saturating_sub(
            SENIORITY_PER_ACTIVE_FRAME.saturating_mul(frame.saturating_sub(end_frame)),
        ),
    };
    let credit = debit.min(retro_credit.saturating_add(accrual.saturating_sub(overlap)));
    // The successor holds what it was credited. A credit capped below the
    // retro it raises (the predecessor held less) holds that retro in
    // proportion, and records the rest as moved out, so a later mover of the
    // same keys finds only what the successor gained.
    let increase: RetroParts = std::array::from_fn(|p| after[p] - base[p]);
    let raised: RetroParts = if credit < retro_credit {
        std::array::from_fn(|p| {
            (u128::from(increase[p]) * u128::from(credit) / u128::from(retro_credit)) as u64
        })
    } else {
        increase
    };
    let successor_held: RetroParts = std::array::from_fn(|p| base[p] + raised[p]);
    let successor_out: RetroParts = std::array::from_fn(|p| {
        (successor_out[p] - successor_out[p].min(raised[p])).saturating_add(increase[p] - raised[p])
    });
    SuccessionAmounts {
        debit,
        accrual,
        credit,
        predecessor: ProverRetro {
            seniority: predecessor.seniority - debit,
            held: Some(left),
            moved: Some(std::array::from_fn(|p| out[p].saturating_add(taken[p]))),
        },
        successor: ProverRetro {
            seniority: successor.seniority.saturating_add(credit),
            held: Some(successor_held),
            moved: (successor.moved.is_some() || successor_out != [0; 5]).then_some(successor_out),
        },
    }
}

/// A succession from `predecessor` to `successor` evaluated at a frame:
/// what moves and everything that blocks it.
#[derive(Debug, Clone)]
pub struct SuccessionPreview {
    pub frame: u64,
    pub successor: [u8; 32],
    pub successor_seniority: u64,
    pub predecessor_address: [u8; 32],
    pub predecessor: Option<PredecessorState>,
    /// The predecessor's last frame with recorded activity.
    pub end_frame: u64,
    pub quiet_frames: u64,
    pub amounts: SuccessionAmounts,
    /// The successor's seniority if the succession applies.
    pub new_seniority: u64,
    pub blockers: Vec<SuccessionBlocker>,
}

impl SuccessionPreview {
    pub fn predecessor_seniority(&self) -> u64 {
        self.predecessor.as_ref().map_or(0, |predecessor| predecessor.seniority)
    }

    /// The predecessor exists and holds no live allocation with recent
    /// activity.
    pub fn predecessor_idle(&self) -> bool {
        self.predecessor.is_some()
            && !self.blockers.iter().any(|blocker| matches!(blocker, SuccessionBlocker::Live { .. }))
    }
}

/// Evaluate a succession at GLOBAL frame `frame` that names `moved`, keys
/// counting for `predecessor`, and `own`, keys counting for the prover at
/// `successor` (vertex `successor_tree`). Lists every blocker, including an
/// inactive network, so a preview can show them all.
#[allow(clippy::too_many_arguments)]
pub fn succession_preview(
    reader: &dyn GlobalReader,
    frame: u64,
    successor: &[u8; 32],
    successor_tree: &VectorCommitmentTree,
    predecessor: &[u8; 32],
    moved: &[Vec<u8>],
    own: &[Vec<u8>],
    retro: &dyn Fn(&[Vec<u8>]) -> RetroParts,
) -> Result<SuccessionPreview> {
    let own_seniority = prover_u64(successor_tree, "Seniority");
    let mut blockers = Vec::new();
    if !seniority_succession_active(frame) {
        blockers.push(SuccessionBlocker::Inactive { epoch: seniority_succession_epoch() });
    }
    if predecessor == successor {
        blockers.push(SuccessionBlocker::SameProver);
    }
    let successor_kick = prover_u64(successor_tree, "KickFrameNumber");
    if kick_bars_rejoin(successor_kick, frame) {
        blockers.push(SuccessionBlocker::SuccessorKicked { frame: successor_kick });
    }
    let quiet_frames = seniority_succession_quiet_frames();
    let state = PredecessorState::read(reader, predecessor)?;
    let (end_frame, amounts) = match &state {
        None => {
            blockers.push(SuccessionBlocker::PredecessorMissing);
            (0, SuccessionAmounts::default())
        }
        Some(state) => {
            if kick_bars_rejoin(state.kick_frame_number, frame) {
                blockers.push(SuccessionBlocker::PredecessorKicked { frame: state.kick_frame_number });
            }
            if state.seniority == 0 {
                blockers.push(SuccessionBlocker::NoSeniority);
            }
            for allocation in &state.allocations {
                if let Some(status) = state.allocation_blocks(allocation, frame) {
                    blockers.push(SuccessionBlocker::Live {
                        filter: allocation.confirmation_filter.clone(),
                        status,
                    });
                }
            }
            let end = state.end_frame();
            let elapsed = frame.saturating_sub(end);
            if elapsed < quiet_frames {
                blockers.push(SuccessionBlocker::Quiet {
                    remaining: quiet_frames - elapsed,
                    until: end.saturating_add(quiet_frames),
                });
            }
            let successor_start = PredecessorState::read(reader, successor)?.and_then(|state| state.start_frame());
            let amounts = succession_amounts(
                &state.retro,
                &ProverRetro::of(successor_tree),
                successor_start,
                moved,
                own,
                frame,
                end,
                retro,
            );
            (end, amounts)
        }
    };
    if amounts.credit == 0 && state.as_ref().is_some_and(|state| state.seniority > 0) {
        blockers.push(SuccessionBlocker::NoGain);
    }
    Ok(SuccessionPreview {
        frame,
        successor: *successor,
        successor_seniority: own_seniority,
        predecessor_address: *predecessor,
        predecessor: state,
        end_frame,
        quiet_frames,
        amounts,
        new_seniority: own_seniority.saturating_add(amounts.credit),
        blockers,
    })
}

/// The retro parts of Ed448 keys, from the compatibility table, as merges
/// and joins credit them: each part is its keys' highest value, so keys of
/// overlapping periods count once.
pub fn retro_parts(public_keys: &[Vec<u8>]) -> RetroParts {
    #[cfg(test)]
    if let Some(retro) = RETRO_FOR_THREAD.with(|cell| cell.get()) {
        return retro(public_keys);
    }
    let peer_ids: Vec<String> = public_keys
        .iter()
        .filter(|key| key.len() == 57)
        .map(|key| super::intrinsic::ed448_pubkey_to_peer_id_string(key))
        .collect();
    if peer_ids.is_empty() {
        RetroParts::default()
    } else {
        crate::seniority_compat::retro_components(&peer_ids)
    }
}

#[cfg(test)]
thread_local! {
    static RETRO_FOR_THREAD: std::cell::Cell<Option<fn(&[Vec<u8>]) -> RetroParts>> = const { std::cell::Cell::new(None) };
}

/// Value keys with `retro` in [`retro_parts`] on the calling thread (tests:
/// synthetic keys are worth nothing in the compatibility table).
#[cfg(test)]
pub(crate) fn set_retro_parts_for_thread(retro: Option<fn(&[Vec<u8>]) -> RetroParts>) {
    RETRO_FOR_THREAD.with(|cell| cell.set(retro));
}

/// The state a decided `ProverSeniorityMerge` writes.
pub struct SeniorityMergePlan {
    pub mode: SeniorityMergeMode,
    /// The submitting prover and its updated vertex.
    pub successor: [u8; 32],
    pub successor_tree: VectorCommitmentTree,
    /// A succession's predecessor and its vertex, debited.
    pub predecessor: Option<([u8; 32], VectorCommitmentTree)>,
    /// Spent markers to write naming the submitting prover.
    pub markers: Vec<[u8; 32]>,
}

impl SeniorityMergePlan {
    /// The submitting prover's seniority after the op.
    pub fn seniority(&self) -> u64 {
        prover_u64(&self.successor_tree, "Seniority")
    }

    /// Stage the plan's writes at `frame`.
    pub fn apply(&self, state: &HypergraphState, frame: u64) -> Result<()> {
        let disc = vertex_adds_discriminator()?;
        let domain = &GLOBAL_INTRINSIC_ADDRESS[..];
        state.set(domain, &self.successor, &disc, frame, vertex_tree_to_blob(&self.successor_tree))?;
        if let Some((address, tree)) = &self.predecessor {
            state.set(domain, address, &disc, frame, vertex_tree_to_blob(tree))?;
        }
        let marker = vertex_tree_to_blob(&create_spent_merge_tree(&self.successor)?);
        for address in &self.markers {
            state.set(domain, address, &disc, frame, marker.clone())?;
        }
        Ok(())
    }
}

/// Decide `op` at GLOBAL frame `frame` over `reader`. `None` before the
/// activation epoch, where the earlier rules apply; otherwise the writes it
/// makes, or why it is refused. `retro` values Ed448 keys
/// ([`retro_parts`] outside tests).
///
/// Every mode requires the submitting prover's vertex, no kick barring it,
/// its signature (checked before any marker is read) and the targets'
/// consent for the mode. A merge must name an unconsumed target and raise
/// the prover's seniority ([`credit_retro`]). A succession requires an
/// idle, quiet, unkicked predecessor holding seniority, and a gain
/// ([`succession_preview`]).
pub fn plan_seniority_merge(
    op: &ProverSeniorityMerge,
    frame: u64,
    reader: &dyn GlobalReader,
    key_manager: &dyn KeyManager,
    retro: &dyn Fn(&[Vec<u8>]) -> RetroParts,
) -> Result<Option<SeniorityMergePlan>> {
    if !seniority_succession_active(frame) {
        return Ok(None);
    }
    if op.merge_targets.is_empty() {
        return Err(refused("no merge targets"));
    }
    let signature = op.public_key_signature_bls48581.as_ref().ok_or_else(|| refused("missing signature"))?;
    let successor: [u8; 32] =
        signature.address.as_slice().try_into().map_err(|_| refused("invalid address length"))?;
    let blob = reader.vertex(&successor)?.ok_or_else(|| refused("prover not found"))?;
    let mut successor_tree = rebuild_vertex_tree_from_blob(&blob);
    let kick = prover_u64(&successor_tree, "KickFrameNumber");
    if kick_bars_rejoin(kick, frame) {
        return Err(refused(SuccessionBlocker::SuccessorKicked { frame: kick }));
    }
    let pubkey = seniority_merge_signer(op, &successor_tree, frame)?
        .ok_or_else(|| refused("the address does not match the prover's key"))?;
    if !verify_seniority_merge_prover_signature(op, &pubkey, key_manager)? {
        return Err(refused("signature verification failed (prover signature)"));
    }
    let markers = op
        .merge_targets
        .iter()
        .map(|target| TargetMarkers::read(reader, &target.prover_public_key))
        .collect::<Result<Vec<_>>>()?;
    let mode = mode_from_markers(&successor, &markers)?;
    let consent = match &mode {
        SeniorityMergeMode::Succession { predecessor } => SeniorityMergeConsent::Succession { predecessor },
        _ => SeniorityMergeConsent::Merge,
    };
    if !verify_seniority_merge_consents(op, &pubkey, key_manager, consent)? {
        return Err(refused(format!("signature verification failed ({mode:?} consent)")));
    }
    let existing = prover_u64(&successor_tree, "Seniority");
    // Keys counting for the submitter, and the others: unconsumed ones in a
    // merge, the predecessor's in a succession. Keys that fit nothing are
    // skipped.
    let (mut own, mut others, mut writes) = (Vec::new(), Vec::new(), Vec::new());
    for (target, marker) in op.merge_targets.iter().zip(&markers) {
        match marker.standing(&successor) {
            TargetStanding::Own => own.push(target.prover_public_key.clone()),
            TargetStanding::Unusable(_) => {}
            TargetStanding::Fresh | TargetStanding::Other(_) => {
                others.push(target.prover_public_key.clone());
                if marker.join.is_some() {
                    writes.push(spent_join_merge_address(&target.prover_public_key)?);
                }
                writes.push(spent_seniority_merge_address(&target.prover_public_key)?);
            }
        }
    }
    match mode {
        SeniorityMergeMode::Legacy => Ok(None),
        SeniorityMergeMode::Merge => {
            if others.is_empty() {
                return Err(refused(
                    "no target is unconsumed: every one already counts for this prover or fits nothing",
                ));
            }
            let ledger = ProverRetro::of(&successor_tree);
            let (credit, parts) = credit_retro(ledger.held, ledger.moved, &others, &own, retro);
            let new = existing.saturating_add(credit);
            if new <= existing {
                return Err(refused(format!(
                    "the targets add no seniority beyond the {existing} this prover holds"
                )));
            }
            write_field(&mut successor_tree, PROVER, "Seniority", &new.to_be_bytes())?;
            set_credited_retro(&mut successor_tree, &parts)?;
            Ok(Some(SeniorityMergePlan {
                mode,
                successor,
                successor_tree,
                predecessor: None,
                markers: writes,
            }))
        }
        SeniorityMergeMode::Succession { predecessor } => {
            let preview = succession_preview(
                reader, frame, &successor, &successor_tree, &predecessor, &others, &own, retro,
            )?;
            if !preview.blockers.is_empty() {
                let reasons: Vec<String> = preview.blockers.iter().map(ToString::to_string).collect();
                return Err(refused(format!(
                    "succession from prover {} refused: {}",
                    hex::encode(predecessor),
                    reasons.join("; ")
                )));
            }
            let blob = reader.vertex(&predecessor)?.ok_or_else(|| refused(SuccessionBlocker::PredecessorMissing))?;
            let mut predecessor_tree = rebuild_vertex_tree_from_blob(&blob);
            // Both ledgers and seniorities: the predecessor drops what moved
            // and records it as moved out; the successor holds it.
            preview.amounts.predecessor.write(&mut predecessor_tree)?;
            preview.amounts.successor.write(&mut successor_tree)?;
            Ok(Some(SeniorityMergePlan {
                mode,
                successor,
                successor_tree,
                predecessor: Some((predecessor, predecessor_tree)),
                markers: writes,
            }))
        }
    }
}

/// A merge a prover's keys can make: the indexes of the keys it names (the
/// unconsumed ones and those already counting for the prover) and what it
/// adds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeProposal {
    pub keys: Vec<usize>,
    pub increment: u64,
}

/// A succession a prover's keys can make: the predecessor, the indexes of
/// the keys it names (those counting for the predecessor, which move, and
/// those counting for the prover), and what GLOBAL would decide now.
#[derive(Debug, Clone)]
pub struct SuccessionCandidate {
    pub predecessor: [u8; 32],
    pub keys: Vec<usize>,
    /// How many of `keys` count for the predecessor and move.
    pub moving: usize,
    pub preview: SuccessionPreview,
}

impl SuccessionCandidate {
    /// GLOBAL would apply it now: what the node submits.
    pub fn submits(&self) -> bool {
        self.preview.blockers.is_empty()
    }
}

/// What a prover's Ed448 keys can do at a frame: each key's markers and
/// standing, the merge they can make and one succession per predecessor.
/// The node submits from it, and `qclient node prover merge --dry-run`
/// prints it, so both decide alike.
#[derive(Debug, Clone)]
pub struct Submissions {
    /// The prover's seniority; `None` without a prover record.
    pub seniority: Option<u64>,
    /// The frame of a kick that bars the prover: then nothing is submitted.
    pub kicked: Option<u64>,
    pub keys: Vec<(TargetMarkers, TargetStanding)>,
    pub merge: Option<MergeProposal>,
    pub successions: Vec<SuccessionCandidate>,
}

/// Plan what the prover at `prover` can submit with `keys` at `frame`.
pub fn plan_submissions(
    reader: &dyn GlobalReader,
    frame: u64,
    prover: &[u8; 32],
    keys: &[Vec<u8>],
    retro: &dyn Fn(&[Vec<u8>]) -> RetroParts,
) -> Result<Submissions> {
    let mut standings = Vec::with_capacity(keys.len());
    for key in keys {
        let markers = TargetMarkers::read(reader, key)?;
        standings.push((markers, markers.standing(prover)));
    }
    let tree = reader.vertex(prover)?.map(|blob| rebuild_vertex_tree_from_blob(&blob));
    let kicked = tree
        .as_ref()
        .map(|tree| prover_u64(tree, "KickFrameNumber"))
        .filter(|&kick| kick_bars_rejoin(kick, frame));
    let mut plan = Submissions {
        seniority: tree.as_ref().map(|tree| prover_u64(tree, "Seniority")),
        kicked,
        keys: standings,
        merge: None,
        successions: Vec::new(),
    };
    let Some(tree) = tree else {
        return Ok(plan);
    };
    if plan.kicked.is_some() {
        return Ok(plan);
    }
    let of = |indexes: &[usize]| -> Vec<Vec<u8>> { indexes.iter().map(|&index| keys[index].clone()).collect() };
    let mut fresh = Vec::new();
    let mut own = Vec::new();
    let mut groups: Vec<([u8; 32], Vec<usize>)> = Vec::new();
    for (index, (_, standing)) in plan.keys.iter().enumerate() {
        match standing {
            TargetStanding::Fresh => fresh.push(index),
            TargetStanding::Own => own.push(index),
            TargetStanding::Other(predecessor) => match groups.iter_mut().find(|(address, _)| address == predecessor) {
                Some((_, group)) => group.push(index),
                None => groups.push((*predecessor, vec![index])),
            },
            TargetStanding::Unusable(_) => {}
        }
    }
    if !fresh.is_empty() {
        let ledger = ProverRetro::of(&tree);
        let (increment, _) = credit_retro(ledger.held, ledger.moved, &of(&fresh), &of(&own), retro);
        if increment > 0 {
            let mut named: Vec<usize> = fresh.iter().chain(&own).copied().collect();
            named.sort_unstable();
            plan.merge = Some(MergeProposal { keys: named, increment });
        }
    }
    for (predecessor, group) in groups {
        let preview = succession_preview(reader, frame, prover, &tree, &predecessor, &of(&group), &of(&own), retro)?;
        let moving = group.len();
        let mut named: Vec<usize> = group.into_iter().chain(own.iter().copied()).collect();
        named.sort_unstable();
        plan.successions.push(SuccessionCandidate { predecessor, keys: named, moving, preview });
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use quil_hypergraph::HypergraphCrdt;
    use quil_types::consensus::{epoch_for_frame, epoch_length_frames, set_seniority_succession_epoch_for_thread};
    use quil_types::crypto::KeyType;
    use quil_types::execution::ShardExecutionEngine;
    use sha2::{Digest, Sha256};

    use crate::global_intrinsic::addressed_signature::AddressedSignature;
    use crate::global_intrinsic::intrinsic::GlobalIntrinsic;
    use crate::global_intrinsic::materialize::{
        create_allocation_vertex_tree, create_prover_vertex_tree, extend_prover_allocation_hyperedge_blob,
        prover_address_from_pubkey,
    };
    use crate::global_intrinsic::prover_join::ProverJoin;
    use crate::global_intrinsic::seniority_merge::SeniorityMerge;
    use crate::global_intrinsic::sig_with_pop::SignatureWithPop;
    use crate::global_intrinsic::verify::{intrinsic_domain, verify_prover_seniority_merge_spent_markers};
    use crate::global_schema::write_type;
    use crate::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

    const ALLOCATION: &str = "allocation:ProverAllocation";
    /// The activation epoch these tests install, and a claim frame past it
    /// and past every kick amnesty: the first frame of epoch 1,250.
    const ACTIVATION: u64 = 1_200;
    const F: u64 = 900_000;
    const X: u8 = 0xA1;
    const Y: u8 = 0xB2;
    const Z: u8 = 0xC3;
    const W: u8 = 0xD4;
    const DATA_SHARD: [u8; 32] = [0x5A; 32];

    fn key(byte: u8) -> Vec<u8> {
        vec![byte; 897]
    }

    fn address(byte: u8) -> [u8; 32] {
        prover_address_from_pubkey(&key(byte)).unwrap()
    }

    fn target(byte: u8) -> Vec<u8> {
        vec![byte; 57]
    }

    /// Retro parts of the test keys: 1 is worth 5,000,000 in the first
    /// retro epoch, 2 1,000,000 in the second, 3 nothing, 5 500 and 7 500 in
    /// the first (the same period), 6 300 in the second, 8 7,000,000 in the
    /// mainnet snapshot. A set takes each part's highest value.
    fn parts(keys: &[Vec<u8>]) -> RetroParts {
        keys.iter().fold(RetroParts::default(), |acc, key| {
            let one: RetroParts = match key[0] {
                1 => [5_000_000, 0, 0, 0, 0],
                2 => [0, 1_000_000, 0, 0, 0],
                5 | 7 => [500, 0, 0, 0, 0],
                6 => [0, 300, 0, 0, 0],
                8 => [0, 0, 0, 0, 7_000_000],
                9 => [800, 0, 0, 0, 0],
                _ => [0; 5],
            };
            parts_max(&acc, &one)
        })
    }

    /// A signature that binds key, message and domain, so a consent made
    /// for another domain, message or frame fails.
    fn fake_signature(len: usize, key: &[u8], message: &[u8], domain: &[u8]) -> Vec<u8> {
        let mut hash = Sha256::new();
        for part in [key, message, domain] {
            hash.update((part.len() as u64).to_be_bytes());
            hash.update(part);
        }
        let mut signature = hash.finalize().to_vec();
        signature.resize(len, 0);
        signature
    }

    struct DomainKeys;
    impl KeyManager for DomainKeys {
        fn validate_signature(&self, _: KeyType, key: &[u8], message: &[u8], signature: &[u8], domain: &[u8]) -> Result<bool> {
            Ok(signature == fake_signature(signature.len(), key, message, domain).as_slice())
        }
    }

    struct AcceptAll;
    impl KeyManager for AcceptAll {
        fn validate_signature(&self, _: KeyType, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<bool> {
            Ok(true)
        }
    }

    #[derive(Clone, Copy)]
    enum Consent {
        Merge,
        Succession(u8),
        /// A succession consent signed for another frame.
        SuccessionAt(u8, u64),
    }

    /// A seniority merge by the prover with key `successor`, its targets
    /// consenting as `consent` says.
    fn claim(successor: u8, frame: u64, targets: &[u8], consent: Consent) -> ProverSeniorityMerge {
        let (message, domain) = match consent {
            Consent::Merge => (key(successor), b"PROVER_SENIORITY_MERGE".as_slice()),
            Consent::Succession(predecessor) => (
                succession_consent_message(&key(successor), &address(predecessor), frame),
                SUCCESSION_DOMAIN,
            ),
            Consent::SuccessionAt(predecessor, signed) => (
                succession_consent_message(&key(successor), &address(predecessor), signed),
                SUCCESSION_DOMAIN,
            ),
        };
        let merge_targets: Vec<SeniorityMerge> = targets
            .iter()
            .map(|&byte| SeniorityMerge {
                signature: fake_signature(114, &target(byte), &message, domain),
                key_type: 0,
                prover_public_key: target(byte),
            })
            .collect();
        let mut signed = frame.to_be_bytes().to_vec();
        for merge_target in &merge_targets {
            signed.extend_from_slice(&merge_target.prover_public_key);
        }
        let domain = intrinsic_domain(b"PROVER_SENIORITY_MERGE").unwrap();
        ProverSeniorityMerge {
            frame_number: frame,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature: fake_signature(666, &key(successor), &signed, &domain),
                address: address(successor).to_vec(),
            }),
            merge_targets,
        }
    }

    fn join(prover: u8, frame: u64, targets: &[u8]) -> Vec<u8> {
        ProverJoin {
            filters: vec![vec![0x7C; 32]],
            frame_number: frame,
            public_key_signature_bls48581: Some(SignatureWithPop {
                signature: vec![0xAA; 666],
                public_key: Some(key(prover)),
                pop_signature: vec![0xCC; 666],
            }),
            merge_targets: targets
                .iter()
                .map(|&byte| SeniorityMerge { signature: vec![byte; 114], key_type: 0, prover_public_key: target(byte) })
                .collect(),
            ..Default::default()
        }
        .to_canonical_bytes()
        .unwrap()
    }

    struct World {
        _db: quil_store::RocksDb,
        crdt: Arc<HypergraphCrdt>,
        state: HypergraphState,
    }

    impl World {
        fn new() -> Self {
            set_seniority_succession_epoch_for_thread(Some(ACTIVATION));
            set_retro_parts_for_thread(Some(parts));
            let db = quil_store::RocksDb::open_in_memory().unwrap();
            let store = Arc::new(quil_store::RocksHypergraphStore::new(db.inner()));
            let crdt = Arc::new(HypergraphCrdt::new(store, Arc::new(quil_hypergraph::testing::StubProver)));
            crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
            let state = HypergraphState::new(crdt.clone());
            Self { _db: db, crdt, state }
        }

        /// X holds 5,000,000 and was last active 10,000 frames before `F`,
        /// on a data shard it no longer re-confirms; Y holds 100,000; key 1
        /// (worth 5,000,000) has a join marker naming X.
        fn eligible() -> Self {
            let world = Self::new();
            world.prover(X, 5_000_000, Some(F - 10_000), 0);
            world.allocation(X, &DATA_SHARD, 1, &[
                ("JoinFrameNumber", F - 100_000),
                ("JoinConfirmFrameNumber", F - 99_000),
                ("Epoch", epoch_for_frame(F) - 10),
                ("LastActiveFrameNumber", F - 10_000),
                ("LastSignedFrameNumber", F - 10_000),
            ]);
            world.prover(Y, 100_000, Some(F - 1), 0);
            world.marker(true, 1, Some(X));
            world
        }

        fn put(&self, at: &[u8; 32], tree: &VectorCommitmentTree) {
            let disc = vertex_adds_discriminator().unwrap();
            self.state.set(&GLOBAL_INTRINSIC_ADDRESS[..], at, &disc, 1, vertex_tree_to_blob(tree)).unwrap();
        }

        fn prover(&self, byte: u8, seniority: u64, last_seniority: Option<u64>, kick: u64) {
            let mut tree = create_prover_vertex_tree(&key(byte), seniority).unwrap();
            if let Some(last) = last_seniority {
                write_field(&mut tree, PROVER, "LastSeniorityFrameNumber", &last.to_be_bytes()).unwrap();
            }
            if kick > 0 {
                write_field(&mut tree, PROVER, "KickFrameNumber", &kick.to_be_bytes()).unwrap();
            }
            self.put(&address(byte), &tree);
        }

        fn set_seniority(&self, byte: u8, seniority: u64) {
            let mut tree = self.tree(byte);
            write_field(&mut tree, PROVER, "Seniority", &seniority.to_be_bytes()).unwrap();
            self.put(&address(byte), &tree);
        }

        fn ledger(&self, byte: u8, held: RetroParts) {
            let mut tree = self.tree(byte);
            set_credited_retro(&mut tree, &held).unwrap();
            self.put(&address(byte), &tree);
        }

        /// An allocation of prover `byte` on `filter`, linked from its
        /// hyperedge, with status byte `status` and the frame fields given.
        fn allocation(&self, byte: u8, filter: &[u8], status: u8, fields: &[(&str, u64)]) {
            let prover = address(byte);
            let at = allocation_address(&key(byte), filter).unwrap();
            let mut tree = create_allocation_vertex_tree(&prover, filter, 0).unwrap();
            write_field(&mut tree, ALLOCATION, "Status", &[status]).unwrap();
            for (field, value) in fields {
                write_field(&mut tree, ALLOCATION, field, &value.to_be_bytes()).unwrap();
            }
            self.put(&at, &tree);
            let disc = hyperedge_adds_discriminator().unwrap();
            let existing = self.state.get(&GLOBAL_INTRINSIC_ADDRESS[..], &prover, &disc).unwrap().unwrap_or_default();
            let blob = extend_prover_allocation_hyperedge_blob(&existing, &[(at, &tree)]).unwrap();
            self.state.set(&GLOBAL_INTRINSIC_ADDRESS[..], &prover, &disc, 1, blob).unwrap();
        }

        /// A spent marker of target `byte` naming prover `owner`, or none.
        fn marker(&self, join: bool, byte: u8, owner: Option<u8>) {
            let at = if join { spent_join_merge_address(&target(byte)) } else { spent_seniority_merge_address(&target(byte)) };
            let tree = match owner {
                Some(owner) => create_spent_merge_tree(&address(owner)).unwrap(),
                None => {
                    let mut tree = VectorCommitmentTree::new();
                    write_type(&mut tree, "merge:SpentMerge").unwrap();
                    tree
                }
            };
            self.put(&at.unwrap(), &tree);
        }

        fn commit(&self) {
            self.state.commit().unwrap();
            self.state.abort();
            self.crdt.commit_with_global_cursor(1, &quil_store::encoding::global_materialized_cursor_key()).unwrap();
        }

        fn tree(&self, byte: u8) -> VectorCommitmentTree {
            rebuild_vertex_tree_from_blob(&self.state.vertex(&address(byte)).unwrap().unwrap())
        }

        fn seniority(&self, byte: u8) -> u64 {
            prover_u64(&self.tree(byte), "Seniority")
        }

        fn markers(&self, byte: u8) -> TargetMarkers {
            TargetMarkers::read(&self.state, &target(byte)).unwrap()
        }

        fn plan(&self, op: &ProverSeniorityMerge, frame: u64) -> Result<Option<SeniorityMergePlan>> {
            plan_seniority_merge(op, frame, &self.state, &DomainKeys, &parts)
        }

        fn apply(&self, op: &ProverSeniorityMerge, frame: u64) {
            self.plan(op, frame).unwrap().expect("active").apply(&self.state, frame).unwrap();
        }

        fn refusal(&self, op: &ProverSeniorityMerge, frame: u64) -> String {
            match self.plan(op, frame) {
                Err(error) => error.to_string(),
                Ok(_) => panic!("the op must be refused"),
            }
        }

        fn rejoin(&self, prover: u8, frame: u64, targets: &[u8]) {
            GlobalIntrinsic::new(Arc::new(AcceptAll)).invoke_step(frame, &join(prover, frame, targets), &self.state).unwrap();
        }

        fn preview(&self, frame: u64) -> SuccessionPreview {
            succession_preview(&self.state, frame, &address(Y), &self.tree(Y), &address(X), &[target(1)], &[], &parts).unwrap()
        }
    }

    fn named(owner: u8) -> Option<MarkerOwner> {
        Some(MarkerOwner::Prover(address(owner)))
    }

    #[test]
    fn the_mode_follows_the_activation_epoch_and_the_markers() {
        let (x, y, z) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let by = |owner: [u8; 32]| TargetMarkers { join: Some(MarkerOwner::Prover(owner)), seniority: None };
        let legacy = TargetMarkers { join: Some(MarkerOwner::Unattributed), seniority: None };
        let merge_prefix = crate::global_intrinsic::TYPE_PROVER_SENIORITY_MERGE;

        set_seniority_succession_epoch_for_thread(Some(u64::MAX));
        for frame in [0, F, u64::MAX - 1] {
            assert_eq!(select_mode(frame, &y, &[by(x)]).unwrap(), SeniorityMergeMode::Legacy, "inert while unset");
            assert!(!crate::global_engine::is_global_type_prefix_at(merge_prefix, frame));
        }

        set_seniority_succession_epoch_for_thread(Some(ACTIVATION));
        let first = ACTIVATION * epoch_length_frames();
        assert_eq!(select_mode(first - 1, &y, &[by(x)]).unwrap(), SeniorityMergeMode::Legacy);
        assert!(!crate::global_engine::is_global_type_prefix_at(merge_prefix, first - 1));
        assert!(crate::global_engine::is_global_type_prefix_at(merge_prefix, first));
        let succession = SeniorityMergeMode::Succession { predecessor: x };
        assert_eq!(select_mode(first, &y, &[by(x)]).unwrap(), succession);
        assert_eq!(select_mode(first, &y, &[by(x), by(y)]).unwrap(), succession, "with the submitter's own keys");
        assert_eq!(select_mode(first, &y, &[by(x), legacy]).unwrap(), succession, "a legacy key is skipped");
        assert_eq!(select_mode(first, &y, &[TargetMarkers::default()]).unwrap(), SeniorityMergeMode::Merge);
        assert_eq!(select_mode(first, &y, &[by(y)]).unwrap(), SeniorityMergeMode::Merge, "the submitter's own markers");
        assert_eq!(select_mode(first, &y, &[legacy]).unwrap(), SeniorityMergeMode::Merge, "skipped, never an error");
        assert!(select_mode(first, &y, &[by(x), by(z)]).is_err(), "two predecessors");
        assert!(select_mode(first, &y, &[by(x), TargetMarkers::default()]).is_err(), "an unconsumed target in a succession");
        let conflicting = TargetMarkers { join: Some(MarkerOwner::Prover(x)), seniority: Some(MarkerOwner::Prover(z)) };
        assert_eq!(conflicting.standing(&y), TargetStanding::Unusable(Unusable::Conflicting));
        assert_eq!(legacy.standing(&y), TargetStanding::Unusable(Unusable::Legacy));
    }

    /// A key's retro counts once per prover however keys are split across
    /// ops: only parts a key raises in the record are credited.
    #[test]
    fn retro_is_credited_once_per_part() {
        set_retro_parts_for_thread(Some(parts));
        let (credit, recorded) = credit_retro(None, None, &[target(5)], &[], &parts);
        assert_eq!((credit, recorded), (500, [500, 0, 0, 0, 0]));
        assert_eq!(credit_retro(Some(recorded), None, &[target(7)], &[], &parts).0, 0, "an overlapping key in a later op");
        assert_eq!(credit_retro(Some(recorded), None, &[target(6)], &[], &parts).0, 300, "a disjoint key");
        assert_eq!(credit_retro(None, None, &[target(7)], &[target(5)], &parts).0, 0, "a first op starts from its own keys");
        assert_eq!(credit_retro(Some([500, 300, 0, 0, 0]), None, &[target(8)], &[], &parts).0, 7_000_000 - 800, "the mainnet part");
    }

    fn bare(seniority: u64) -> ProverRetro {
        ProverRetro { seniority, held: None, moved: None }
    }

    /// What moves: the keys' retro the predecessor holds, and its accrual
    /// (all of it to the first mover from a predecessor without a ledger,
    /// else pro rata), less the successor's overlapping accrual; never more
    /// than the predecessor loses.
    #[test]
    fn a_succession_moves_the_keys_retro_and_the_accrual() {
        let moved = [target(1)];
        let end = F - 100_000;
        // No ledger: the first mover takes the whole accrual.
        let amounts = succession_amounts(&bare(6_300_000), &bare(0), None, &moved, &[], F, end, &parts);
        assert_eq!((amounts.debit, amounts.accrual, amounts.credit), (6_300_000, 1_300_000, 6_300_000));
        assert_eq!(
            amounts.predecessor,
            ProverRetro { seniority: 0, held: Some([0; 5]), moved: Some([5_000_000, 0, 0, 0, 0]) }
        );
        // A ledger of 6,000,000 and 300,000 accrual: key 1 holds 5/6.
        let x = ProverRetro { seniority: 6_300_000, held: Some([5_000_000, 1_000_000, 0, 0, 0]), moved: None };
        let first = succession_amounts(&x, &bare(0), None, &moved, &[], F, end, &parts);
        assert_eq!((first.debit, first.accrual, first.credit), (5_250_000, 250_000, 5_250_000));
        // The second mover still finds its key and its accrual share.
        let second = succession_amounts(&first.predecessor, &bare(0), None, &[target(2)], &[], F, end, &parts);
        assert_eq!((second.debit, second.credit, second.predecessor.seniority), (1_050_000, 1_050_000, 0));
        // The successor's accrual earned while the predecessor was active
        // (100,000 beyond 10 × 1,000 frames) is taken off the accrual, unless
        // it started after the predecessor stopped.
        let overlapping = succession_amounts(&x, &bare(100_000), None, &moved, &[], F, F - 1_000, &parts);
        assert_eq!((overlapping.debit, overlapping.credit), (5_250_000, 5_160_000));
        let later = succession_amounts(&x, &bare(100_000), Some(F - 500), &moved, &[], F, F - 1_000, &parts);
        assert_eq!(later.credit, 5_250_000);
        // Retro the successor already holds: the predecessor loses it, the
        // successor gains nothing, and its ledger records nothing new.
        let holder = ProverRetro { seniority: 5_000_000, held: Some([5_000_000, 0, 0, 0, 0]), moved: None };
        let amounts = succession_amounts(&bare(5_000_000), &holder, None, &moved, &[], F, end, &parts);
        assert_eq!((amounts.debit, amounts.credit, amounts.successor.held), (5_000_000, 0, holder.held));
        // Never more than the predecessor holds; the successor then holds the
        // retro in proportion and records the rest as moved out, so a later
        // mover of the key finds only what it gained.
        let capped = succession_amounts(&bare(3_000_000), &bare(0), None, &moved, &[], F, end, &parts);
        assert_eq!((capped.debit, capped.credit), (3_000_000, 3_000_000));
        assert_eq!(
            capped.successor,
            ProverRetro { seniority: 3_000_000, held: Some([3_000_000, 0, 0, 0, 0]), moved: Some([2_000_000, 0, 0, 0, 0]) }
        );
        let onward = succession_amounts(&capped.successor, &bare(0), None, &moved, &[], F, end, &parts);
        assert_eq!(onward.debit, 3_000_000);
    }

    /// Two keys of one period are debited once; a part missing from a
    /// bootstrapped ledger is proven by the key's marker.
    #[test]
    fn a_ledger_debits_a_period_once_and_trusts_a_marker_for_a_missing_part() {
        let end = F - 100_000;
        let x = ProverRetro { seniority: 10_000, held: Some([500, 0, 0, 0, 0]), moved: None };
        let first = succession_amounts(&x, &bare(0), None, &[target(5)], &[], F, end, &parts);
        assert_eq!(first.predecessor.held, Some([0; 5]));
        let second = succession_amounts(&first.predecessor, &bare(0), None, &[target(7)], &[], F, end, &parts);
        assert_eq!(second.credit, 0, "key 7 shares key 5's period, already moved");
        let bootstrapped = ProverRetro { seniority: 6_000_000, held: Some([0, 1_000_000, 0, 0, 0]), moved: None };
        let amounts = succession_amounts(&bootstrapped, &bare(0), None, &[target(1)], &[], F, end, &parts);
        assert_eq!(amounts.debit, 5_000_000, "key 1's part, proven by its marker");
    }

    #[test]
    fn a_succession_moves_the_seniority_and_rewrites_the_markers() {
        let world = World::eligible();
        let op = claim(Y, F, &[1], Consent::Succession(X));
        let plan = world.plan(&op, F).unwrap().expect("active");
        assert_eq!(plan.mode, SeniorityMergeMode::Succession { predecessor: address(X) });
        assert_eq!(plan.seniority(), 5_100_000);
        plan.apply(&world.state, F).unwrap();
        assert_eq!((world.seniority(X), world.seniority(Y)), (0, 5_100_000));
        assert_eq!(world.markers(1), TargetMarkers { join: named(Y), seniority: named(Y) });
        assert_eq!(credited_retro(&world.tree(Y)), Some([5_000_000, 0, 0, 0, 0]), "recorded on the successor");
        assert_eq!(
            ProverRetro::of(&world.tree(X)),
            ProverRetro { seniority: 0, held: Some([0; 5]), moved: Some([5_000_000, 0, 0, 0, 0]) }
        );
        assert_eq!(prover_u64(&world.tree(X), "LastSeniorityFrameNumber"), F - 10_000, "the predecessor keeps its history");
    }

    #[test]
    fn a_consent_signed_for_the_old_domain_another_predecessor_or_frame_is_refused() {
        let world = World::eligible();
        world.prover(Z, 1, Some(F - 50_000), 0);
        for consent in [Consent::Merge, Consent::Succession(Z), Consent::SuccessionAt(X, F - 5)] {
            assert!(world.refusal(&claim(Y, F, &[1], consent), F).contains("signature verification failed"));
        }
        assert_eq!((world.seniority(X), world.seniority(Y)), (5_000_000, 100_000));
    }

    #[test]
    fn a_kicked_live_or_recent_predecessor_is_refused() {
        type Setup = fn(&World);
        let cases: [(&str, Setup, &str); 9] = [
            ("kicked", |w| w.prover(X, 5_000_000, Some(F - 10_000), 850_000), "kicked at frame 850000"),
            ("no seniority", |w| w.prover(X, 0, Some(F - 10_000), 0), "holds no seniority"),
            ("active", |w| w.allocation(X, &[0x6B; 32], 1, &[("JoinConfirmFrameNumber", F - 99_000), ("Epoch", epoch_for_frame(F)), ("LastActiveFrameNumber", F - 100)]), "is Active"),
            ("joining", |w| w.allocation(X, &[0x6B; 32], 0, &[("JoinFrameNumber", F - 100)]), "is Joining"),
            ("leaving", |w| w.allocation(X, &[0x6B; 32], 3, &[("LeaveFrameNumber", F - 100)]), "is Leaving"),
            ("paused", |w| w.allocation(X, &[0x6B; 32], 2, &[("PauseFrameNumber", F - 500)]), "is Paused"),
            ("global active", |w| w.allocation(X, &[], 1, &[("LastActiveFrameNumber", F - 100)]), "global allocation is Active"),
            ("quiet", |w| w.prover(X, 5_000_000, Some(F - 1_000), 0), "440 more frames without activity (until frame 900440)"),
            ("successor kicked", |w| w.prover(Y, 100_000, Some(F - 1), 850_000), "this prover was kicked at frame 850000"),
        ];
        for (case, setup, reason) in cases {
            let world = World::eligible();
            setup(&world);
            let refusal = world.refusal(&claim(Y, F, &[1], Consent::Succession(X)), F);
            assert!(refusal.contains(reason), "{case}: {refusal}");
            assert_eq!(world.seniority(Y), 100_000, "{case}: the successor keeps its seniority");
            assert_eq!(world.markers(1).join, named(X), "{case}: the markers stay");
        }
        // An allocation past its epoch is idle: the eligible world has one.
        assert!(World::eligible().preview(F).blockers.is_empty());
    }

    /// A Paused allocation never expires; with no activity for the quiet
    /// period it counts as idle for a succession. A prover that re-confirms
    /// every epoch still blocks, and so does an Active global allocation,
    /// which records no activity while its prover produces GLOBAL frames.
    #[test]
    fn allocations_left_behind_count_as_idle_after_the_quiet_period() {
        let world = World::eligible();
        world.allocation(X, &[0x6B; 32], 2, &[("JoinFrameNumber", F - 90_000), ("PauseFrameNumber", F - 20_000)]);
        assert_eq!(world.preview(F).blockers, vec![]);
        world.apply(&claim(Y, F, &[1], Consent::Succession(X)), F);
        assert_eq!(world.seniority(Y), 5_100_000);

        let world = World::eligible();
        world.allocation(X, &[], 1, &[("JoinFrameNumber", F - 50_000)]);
        assert_eq!(
            world.preview(F).blockers,
            vec![SuccessionBlocker::Live { filter: vec![], status: EffectiveStatus::Active }]
        );

        let world = World::eligible();
        world.allocation(X, &[0x6B; 32], 1, &[
            ("JoinConfirmFrameNumber", F - 99_000),
            ("Epoch", epoch_for_frame(F)),
            ("LastActiveFrameNumber", F - 300),
        ]);
        let blockers = world.preview(F).blockers;
        assert!(blockers.contains(&SuccessionBlocker::Live { filter: vec![0x6B; 32], status: EffectiveStatus::Active }), "{blockers:?}");
        assert!(blockers.iter().any(|blocker| matches!(blocker, SuccessionBlocker::Quiet { .. })));
    }

    #[test]
    fn markers_without_one_predecessor_are_refused_or_skipped() {
        // Two predecessors.
        let world = World::eligible();
        world.prover(Z, 1, Some(F - 50_000), 0);
        world.marker(true, 2, Some(Z));
        assert!(world.refusal(&claim(Y, F, &[1, 2], Consent::Succession(X)), F).contains("count for different provers"));
        // An unconsumed key in a succession.
        let world = World::eligible();
        assert!(world.refusal(&claim(Y, F, &[1, 2], Consent::Succession(X)), F).contains("unconsumed target"));
        // A key whose markers fit nothing is skipped: left alone, so the op
        // names nothing to credit.
        let world = World::eligible();
        world.marker(false, 1, None);
        assert!(world.refusal(&claim(Y, F, &[1], Consent::Merge), F).contains("no target is unconsumed"));
        assert_eq!(world.markers(1).seniority, Some(MarkerOwner::Unattributed));
        // X == Y: markers naming the submitter select a merge, which the
        // succession consent does not sign.
        let world = World::eligible();
        world.marker(true, 1, Some(Y));
        assert!(world.refusal(&claim(Y, F, &[1], Consent::Succession(Y)), F).contains("signature verification failed"));
        let preview = succession_preview(&world.state, F, &address(Y), &world.tree(Y), &address(Y), &[], &[], &parts).unwrap();
        assert!(preview.blockers.contains(&SuccessionBlocker::SameProver));
    }

    #[test]
    fn a_rejoin_that_cleared_the_prover_field_still_dates_the_predecessor() {
        let world = World::eligible();
        // A rejoin wrote the vertex without `LastSeniorityFrameNumber`; its
        // allocation still records the predecessor's last signed frame.
        world.prover(X, 5_000_000, None, 0);
        world.allocation(X, &[0x6B; 32], 1, &[
            ("JoinFrameNumber", F - 30_000),
            ("Epoch", epoch_for_frame(F) - 2),
            ("LastSignedFrameNumber", F - 1_000),
        ]);
        let preview = world.preview(F);
        assert_eq!(preview.predecessor.as_ref().unwrap().last_seniority_frame_number, 0);
        assert_eq!(preview.end_frame, F - 1_000);
        assert_eq!(preview.blockers, vec![SuccessionBlocker::Quiet { remaining: 440, until: F + 440 }]);
        assert!(world.preview(F + 440).blockers.is_empty());
    }

    #[test]
    fn a_replay_and_a_second_claim_in_the_same_frame_are_refused() {
        let world = World::eligible();
        world.prover(Z, 0, Some(F - 50_000), 0);
        let by_y = claim(Y, F, &[1], Consent::Succession(X));
        let by_z = claim(Z, F, &[1], Consent::Succession(X));
        world.apply(&by_y, F);
        // Same frame: the second claim reads the first one's writes.
        assert!(world.plan(&by_z, F).is_err());
        assert!(world.plan(&by_y, F).is_err());
        // A later frame within the op's freshness window.
        assert!(world.plan(&by_y, F + 1).is_err());
        assert_eq!((world.seniority(X), world.seniority(Y), world.seniority(Z)), (0, 5_100_000, 0));
    }

    #[test]
    fn seniority_chains_from_successor_to_successor() {
        let world = World::eligible();
        // Y holds no allocation and last accrued long ago, so it is idle.
        world.prover(Y, 100_000, Some(F - 50_000), 0);
        world.prover(Z, 0, Some(F - 50_000), 0);
        world.apply(&claim(Y, F, &[1], Consent::Succession(X)), F);
        assert_eq!(world.seniority(Y), 5_100_000);
        // Y records key 1's retro: its 100,000 beyond it is accrual, which
        // moves pro rata (all of it: key 1 is Y's whole record).
        world.apply(&claim(Z, F + 5, &[1], Consent::Succession(Y)), F + 5);
        assert_eq!((world.seniority(X), world.seniority(Y), world.seniority(Z)), (0, 0, 5_100_000));
        assert_eq!(world.markers(1), TargetMarkers { join: named(Z), seniority: named(Z) });
    }

    /// Per-key succession. From a predecessor without a ledger the first
    /// mover takes its accrual too; with a ledger each mover takes its keys'
    /// retro and accrual share. No key or seniority counts twice.
    #[test]
    fn a_partial_succession_moves_only_the_named_keys_and_counts_each_once() {
        let total = |world: &World| world.seniority(X) + world.seniority(Y) + world.seniority(W);
        let world = World::eligible();
        world.prover(X, 6_300_000, Some(F - 10_000), 0);
        world.marker(true, 2, Some(X));
        world.prover(W, 0, Some(F - 50_000), 0);
        let before = total(&world);
        world.apply(&claim(Y, F, &[1], Consent::Succession(X)), F);
        assert_eq!((world.seniority(X), world.seniority(Y)), (0, 6_400_000), "the first mover takes X's accrual too");
        assert!(world.refusal(&claim(W, F, &[2], Consent::Succession(X)), F).contains("holds no seniority"));
        assert_eq!(total(&world), before);

        let world = World::eligible();
        world.prover(X, 6_300_000, Some(F - 10_000), 0);
        world.ledger(X, [5_000_000, 1_000_000, 0, 0, 0]);
        world.marker(true, 2, Some(X));
        world.prover(W, 0, Some(F - 50_000), 0);
        let before = total(&world);
        world.apply(&claim(Y, F, &[1], Consent::Succession(X)), F);
        assert_eq!((world.seniority(X), world.seniority(Y)), (1_050_000, 5_350_000));
        assert_eq!(world.markers(2).join, named(X), "the other key still counts for X");
        // X merges its other key: it already counts for X.
        assert!(world.refusal(&claim(X, F, &[2], Consent::Merge), F).contains("no target is unconsumed"));
        // Y cannot move key 1 again: it counts for Y now.
        assert!(world.refusal(&claim(Y, F, &[1], Consent::Succession(X)), F).contains("signature verification failed"));
        assert!(world.refusal(&claim(Y, F, &[1], Consent::Merge), F).contains("no target is unconsumed"));
        // Key 2's holder moves its share to W.
        world.apply(&claim(W, F, &[2], Consent::Succession(X)), F);
        assert_eq!((world.seniority(X), world.seniority(W)), (0, 1_050_000));
        assert_eq!(total(&world), before, "seniority is moved, never created");
        // X rejoins with the moved key and a fresh one: nothing comes back.
        world.rejoin(X, F + 1, &[2, 3]);
        assert_eq!(world.seniority(X), 0);
        assert_eq!(world.markers(2).join, named(W));
        assert_eq!(world.markers(3).join, named(X), "a fresh key is stamped");
        assert_eq!(ProverRetro::of(&world.tree(X)).moved, Some([5_000_000, 1_000_000, 0, 0, 0]), "a rejoin keeps the ledger");
    }

    /// X's own key whose period already moved out holds nothing there: a key
    /// of that period moved back, or merged fresh, is credited in full, and
    /// the own key cannot carry the period away a second time.
    #[test]
    fn an_own_key_of_a_period_that_moved_out_holds_nothing() {
        let setup = || {
            let world = World::eligible();
            world.prover(X, 500, Some(F - 10_000), 0);
            world.marker(true, 5, Some(X));
            world.marker(true, 7, Some(X));
            world.prover(Y, 0, Some(F - 50_000), 0);
            world.apply(&claim(Y, F, &[5], Consent::Succession(X)), F);
            assert_eq!((world.seniority(X), world.seniority(Y)), (0, 500));
            world
        };
        // Y accrues 1,000; X moves key 5 back, naming its own key 7 too.
        let world = setup();
        world.set_seniority(Y, 1_500);
        world.apply(&claim(X, F + 5, &[5, 7], Consent::Succession(Y)), F + 5);
        assert_eq!((world.seniority(X), world.seniority(Y)), (1_500, 0), "nothing is destroyed");
        // Without accrual the move back is still a gain.
        let world = setup();
        world.apply(&claim(X, F + 5, &[5, 7], Consent::Succession(Y)), F + 5);
        assert_eq!((world.seniority(X), world.seniority(Y)), (500, 0));
        // A fresh key of the moved period, merged with key 7, counts in full.
        let world = setup();
        world.apply(&claim(X, F, &[9, 7], Consent::Merge), F);
        assert_eq!(world.seniority(X), 800);
        // Merging a key of another period with key 7 does not hand key 7 a
        // period it no longer holds.
        let world = setup();
        world.prover(Z, 0, Some(F - 50_000), 0);
        world.apply(&claim(X, F, &[6, 7], Consent::Merge), F);
        assert_eq!(world.seniority(X), 300);
        assert_eq!(credited_retro(&world.tree(X)), Some([0, 300, 0, 0, 0]));
        assert!(world.refusal(&claim(Z, F, &[7], Consent::Succession(X)), F).contains("would not raise"));
    }

    /// A successor that moves keys back is credited them again.
    #[test]
    fn moving_keys_back_restores_them() {
        let world = World::eligible();
        world.prover(Y, 100_000, Some(F - 50_000), 0);
        world.apply(&claim(Y, F, &[1], Consent::Succession(X)), F);
        world.apply(&claim(X, F + 5, &[1], Consent::Succession(Y)), F + 5);
        assert_eq!((world.seniority(X), world.seniority(Y)), (5_100_000, 0));
        assert_eq!(
            ProverRetro::of(&world.tree(X)),
            ProverRetro { seniority: 5_100_000, held: Some([5_000_000, 0, 0, 0, 0]), moved: Some([0; 5]) }
        );
    }

    /// A join reads both markers: a key another prover merged counts for
    /// that prover, so a later join of it credits nothing and leaves its
    /// markers consistent.
    #[test]
    fn a_join_skips_a_key_another_prover_merged() {
        let world = World::new();
        world.prover(Y, 0, Some(F - 1), 0);
        world.apply(&claim(Y, F, &[5], Consent::Merge), F);
        assert_eq!(world.seniority(Y), 500);
        world.rejoin(Z, F + 1, &[5]);
        assert_eq!(world.seniority(Z), 0);
        assert_eq!(world.markers(5), TargetMarkers { join: None, seniority: named(Y) });
        assert_eq!(world.markers(5).standing(&address(Y)), TargetStanding::Own);
    }

    /// After the markers name the successor, neither its rejoin nor a merge
    /// of the same key adds the predecessor's seniority again.
    #[test]
    fn a_successor_rejoin_or_merge_credits_nothing_more() {
        let world = World::eligible();
        world.apply(&claim(Y, F, &[1], Consent::Succession(X)), F);
        world.rejoin(Y, F + 1, &[1]);
        assert_eq!(world.seniority(Y), 5_100_000);
        assert!(world.refusal(&claim(Y, F + 1, &[1], Consent::Merge), F + 1).contains("no target is unconsumed"));
    }

    #[test]
    fn a_merge_must_add_an_unconsumed_targets_seniority() {
        let world = World::new();
        world.prover(Y, 100, Some(F - 1), 0);
        let op = claim(Y, F, &[5], Consent::Merge);
        let plan = world.plan(&op, F).unwrap().unwrap();
        assert_eq!(plan.mode, SeniorityMergeMode::Merge);
        assert_eq!(plan.seniority(), 600);
        assert_eq!(plan.markers, vec![spent_seniority_merge_address(&target(5)).unwrap()]);
        // An established prover still gains what a new key adds.
        world.prover(Y, 600_000, Some(F - 1), 0);
        assert_eq!(world.plan(&op, F).unwrap().unwrap().seniority(), 600_500);
        // A key worth nothing adds nothing.
        assert!(world.refusal(&claim(Y, F, &[3], Consent::Merge), F).contains("add no seniority"));
        set_seniority_succession_epoch_for_thread(Some(u64::MAX));
        assert!(world.plan(&op, F).unwrap().is_none(), "the earlier rules apply");
    }

    /// Same-prover idempotency: a merge may name keys that already count for
    /// the prover, and they add nothing.
    #[test]
    fn keys_that_already_count_for_the_prover_add_nothing() {
        let world = World::new();
        world.prover(Y, 600, Some(F - 1), 0);
        world.marker(true, 5, Some(Y));
        let replay = claim(Y, F, &[5], Consent::Merge);
        assert!(world.refusal(&replay, F).contains("no target is unconsumed"));
        // {consumed, fresh}: only what the fresh key adds.
        let both = claim(Y, F, &[5, 6], Consent::Merge);
        let plan = world.plan(&both, F).unwrap().unwrap();
        assert_eq!(plan.seniority(), 900, "600 + 300");
        assert_eq!(plan.markers, vec![spent_seniority_merge_address(&target(6)).unwrap()], "only the fresh key is stamped");
        assert!(world.refusal(&claim(Y, F, &[5, 7], Consent::Merge), F).contains("add no seniority"), "key 7 overlaps key 5");
        plan.apply(&world.state, F).unwrap();
        assert!(world.plan(&both, F + 1).is_err(), "a replay names no unconsumed key");
        assert_eq!(world.seniority(Y), 900);
        // Before activation a consumed target refuses the merge outright.
        let earlier = verify_prover_seniority_merge_spent_markers(&replay, |at: &[u8; 32]| world.state.vertex(at));
        assert!(earlier.is_err());
        // A kicked prover restores nothing.
        world.prover(Y, 0, Some(F - 1), 850_000);
        assert!(world.refusal(&claim(Y, F, &[3], Consent::Merge), F).contains("kicked"));
    }

    /// Ops naming one concurrent key each credit the period once.
    #[test]
    fn keys_split_across_ops_count_once() {
        let world = World::new();
        world.prover(Y, 0, Some(F - 1), 0);
        world.apply(&claim(Y, F, &[5], Consent::Merge), F);
        assert!(world.refusal(&claim(Y, F, &[7], Consent::Merge), F).contains("add no seniority"));
        world.apply(&claim(Y, F, &[6], Consent::Merge), F);
        assert_eq!(world.seniority(Y), 800);
        assert_eq!(credited_retro(&world.tree(Y)), Some([500, 300, 0, 0, 0]));
        // A prover credited before activation starts from the own keys its
        // first op names.
        let world = World::new();
        world.prover(Y, 500, Some(F - 1), 0);
        world.marker(true, 5, Some(Y));
        assert!(world.refusal(&claim(Y, F, &[5, 7], Consent::Merge), F).contains("add no seniority"));
    }

    /// The node and the dry run plan from the same function: keys group by
    /// the prover they count for, the prover's own keys ride along, and a
    /// succession is submitted when GLOBAL would apply it.
    #[test]
    fn submissions_group_keys_by_the_prover_they_count_for() {
        let world = World::eligible();
        world.marker(true, 2, Some(Y));
        world.marker(true, 4, None);
        let keys: Vec<Vec<u8>> = [1u8, 2, 3, 4].iter().map(|&byte| target(byte)).collect();
        let plan = plan_submissions(&world.state, F, &address(Y), &keys, &parts).unwrap();
        assert_eq!(plan.seniority, Some(100_000));
        let standings: Vec<TargetStanding> = plan.keys.iter().map(|(_, standing)| *standing).collect();
        assert_eq!(standings, vec![
            TargetStanding::Other(address(X)),
            TargetStanding::Own,
            TargetStanding::Fresh,
            TargetStanding::Unusable(Unusable::Legacy),
        ]);
        assert_eq!(plan.merge, None, "the fresh key is worth nothing");
        assert_eq!(plan.successions.len(), 1);
        let candidate = &plan.successions[0];
        assert_eq!((candidate.predecessor, candidate.keys.clone(), candidate.moving), (address(X), vec![0, 1], 1));
        assert!(candidate.submits());
        assert_eq!(candidate.preview.new_seniority, 5_100_000);
        // A successor whose seniority exceeds the keys' retro still submits.
        world.prover(Y, 3_000_000, Some(F - 1), 0);
        let plan = plan_submissions(&world.state, F, &address(Y), &keys[..1], &parts).unwrap();
        assert!(plan.successions[0].submits());
        assert_eq!(plan.successions[0].preview.new_seniority, 8_000_000);
        // A kicked prover submits nothing.
        world.prover(Y, 3_000_000, Some(F - 1), 850_000);
        let plan = plan_submissions(&world.state, F, &address(Y), &keys, &parts).unwrap();
        assert_eq!(plan.kicked, Some(850_000));
        assert!(plan.merge.is_none() && plan.successions.is_empty());
        // Before activation it shows the succession, blocked.
        world.prover(Y, 100_000, Some(F - 1), 0);
        set_seniority_succession_epoch_for_thread(Some(u64::MAX));
        let plan = plan_submissions(&world.state, F, &address(Y), &keys[..1], &parts).unwrap();
        assert!(!plan.successions[0].submits());
    }

    /// Validation and materialization run the same plan over the same
    /// state: the intrinsic's validate and its execution agree on every
    /// case, and accept the eligible succession.
    #[test]
    fn validation_and_materialization_agree() {
        type Setup = fn(&World);
        let cases: [(&str, Setup, Consent, bool); 7] = [
            ("eligible", |_| {}, Consent::Succession(X), true),
            ("old domain", |_| {}, Consent::Merge, false),
            ("quiet", |w| w.prover(X, 5_000_000, Some(F - 1_000), 0), Consent::Succession(X), false),
            ("live", |w| w.allocation(X, &[], 1, &[("LastActiveFrameNumber", F - 100)]), Consent::Succession(X), false),
            ("legacy marker", |w| w.marker(false, 1, None), Consent::Succession(X), false),
            ("kicked", |w| w.prover(X, 5_000_000, Some(F - 10_000), 850_000), Consent::Succession(X), false),
            ("own key only", |w| w.marker(true, 1, Some(Y)), Consent::Merge, false),
        ];
        for (case, setup, consent, accepted) in cases {
            let world = World::eligible();
            setup(&world);
            world.commit();
            let bytes = claim(Y, F, &[1], consent).to_canonical_bytes().unwrap();
            let intrinsic = GlobalIntrinsic::new(Arc::new(DomainKeys)).with_hypergraph(world.crdt.clone());
            let validated = matches!(intrinsic.validate(F, &bytes, Some(&world.tree(Y)), None), Ok(true));
            let executed = intrinsic.invoke_step(F, &bytes, &HypergraphState::new(world.crdt.clone())).is_ok();
            assert_eq!(validated, executed, "{case}");
            assert_eq!(validated, accepted, "{case}");
        }
    }

    /// Engines route a `ProverSeniorityMerge` (0x031A) to the intrinsic only
    /// from the activation epoch. Before it, and on a build with no epoch
    /// set, every node skips it alike: no state changes.
    #[test]
    fn an_engine_executes_a_succession_only_from_activation() {
        let world = World::eligible();
        world.commit();
        let bundle = CanonicalMessageBundle {
            requests: vec![Some(CanonicalMessageRequest::wrap(claim(Y, F, &[1], Consent::Succession(X)).to_canonical_bytes().unwrap()).unwrap())],
            timestamp: 0,
        }
        .to_canonical_bytes()
        .unwrap();
        let engine = crate::engines::GlobalExecutionEngine::new_with_intrinsic(
            Arc::new(quil_hypergraph::testing::StubProver),
            Arc::new(DomainKeys),
            world.crdt.clone(),
            Arc::new(crate::testing::NoopClockStore),
            None,
            None,
        );
        let global = [0xFFu8; 32];
        let fee = num_bigint::BigInt::from(1);
        let read = |byte: u8| {
            let state = HypergraphState::new(world.crdt.clone());
            prover_u64(&rebuild_vertex_tree_from_blob(&state.vertex(&address(byte)).unwrap().unwrap()), "Seniority")
        };

        set_seniority_succession_epoch_for_thread(Some(u64::MAX));
        engine.validate_message(F, &global, &bundle).unwrap();
        engine.process_message(F, &fee, &global, &bundle).unwrap();
        assert_eq!((read(X), read(Y)), (5_000_000, 100_000), "inert while no epoch is set");
        // The intrinsic itself refuses it under the earlier rules.
        let op = claim(Y, F, &[1], Consent::Succession(X)).to_canonical_bytes().unwrap();
        let intrinsic = GlobalIntrinsic::new(Arc::new(DomainKeys)).with_hypergraph(world.crdt.clone());
        assert!(!matches!(intrinsic.validate(F, &op, Some(&world.tree(Y)), None), Ok(true)));
        assert!(intrinsic.invoke_step(F, &op, &HypergraphState::new(world.crdt.clone())).is_err());

        set_seniority_succession_epoch_for_thread(Some(ACTIVATION));
        engine.validate_message(F, &global, &bundle).unwrap();
        engine.process_message(F, &fee, &global, &bundle).unwrap();
        assert_eq!((read(X), read(Y)), (0, 5_100_000));
        assert!(engine.validate_message(F + 1, &global, &bundle).is_err(), "a replay is refused");
    }

    /// A rejoin rewrites the prover vertex; from activation it keeps the
    /// accrual's once-per-frame key, so a prover active on another shard
    /// cannot accrue twice in its rejoin frame.
    #[test]
    fn a_rejoin_keeps_the_accrual_key_from_activation() {
        let rejoin = |epoch: u64| {
            let world = World::new();
            set_seniority_succession_epoch_for_thread(Some(epoch));
            world.prover(Y, 1_000, Some(F), 0);
            world.allocation(Y, &DATA_SHARD, 1, &[("JoinConfirmFrameNumber", F - 99_000), ("Epoch", epoch_for_frame(F))]);
            world.rejoin(Y, F, &[]);
            let tree = world.tree(Y);
            (prover_u64(&tree, "Seniority"), read_field(&tree, PROVER, "LastSeniorityFrameNumber"))
        };
        assert_eq!(rejoin(ACTIVATION), (1_000, Some(F.to_be_bytes().to_vec())));
        assert_eq!(rejoin(u64::MAX), (1_000, None), "the earlier rewrite clears it");
    }
}
