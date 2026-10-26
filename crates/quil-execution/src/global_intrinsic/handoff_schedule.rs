//! Production callers of [`super::initialize`] and [`super::schedule`].
//!
//! Runs inside the once-per-frame global maintenance pass, over COMMITTED
//! prover state only, so every materializing node authorizes the same sessions
//! and requests. Wire messages never reach this module: they can only supply
//! closing certificates for requests created here.
//!
//! Membership is reconciled at storage-epoch boundaries, where the epoch-aligned
//! prover lifecycle changes committee eligibility. Splits and merges of a
//! managed application wait for every source committee's terminal seal before
//! the grid flips and allocations move.
//!
//! A source committee that can no longer assemble a quorum never seals. After
//! [`FENCE_AFTER_EPOCHS`] epochs (one from [`super::early_fence_frame`]:
//! [`fence_due_frame`]) GLOBAL fences it instead
//! ([`fence_stalled_sources`]): the session ends at the last data frame GLOBAL
//! executed for it (its `tip`), frames beyond that are refused like frames after
//! a seal, and the successor is authorized from that checkpoint. A fenced
//! checkpoint carries no certified outgoing-history root; its successor accepts
//! it on state roots alone. Unfinalized work, and finalized frames GLOBAL never
//! executed, are lost with the fenced session.

use quil_cw_consensus::falcon_base::FalconPublicKey;
use quil_cw_consensus::handoff::Session;
use quil_types::consensus::CommitteeHandoffPolicy;
use quil_types::error::{QuilError, Result};
use quil_types::store::{PendingShardChange, ShardChangeKind};

use super::{
    activate_with, head, initialize, invalid, origins, read, request, schedule, seal_key, session_tip,
    status, write, DesiredCommittee, Records, Status,
};
use crate::hypergraph_state::HypergraphState;
use crate::prover_registry::CommittedProverScan;

/// Outcome for one due topology change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TopologyGate {
    /// No session governs the sources, or their successors are authorized: the
    /// grid flip and allocation move may be staged in this frame.
    Apply,
    /// Sources are closing (or cannot be scheduled yet); keep the pending record.
    Wait,
    /// The change has lost its reason: none of its successors would have a
    /// member (the parent's provers have all left since it was proposed).
    /// Consume the pending record without applying it; a shard that becomes
    /// over-crowded again is proposed again. Recorded in GLOBAL state so a node
    /// without a prover scan (a regular) drops it too.
    Drop,
}

/// Sorted, unique Falcon keys of the provers committee-eligible on `filter`.
/// Keys that are not well-formed Falcon public keys cannot sign in a session
/// and are left out deterministically.
///
/// While a step of the release eligibility schedule applies at `frame`, the
/// frame the session is formed at, only allocations whose recorded release is
/// at least that step's minimum are seated; one without a recorded release is
/// not ([`super::super::prover_release::seat_eligible`]). The recorded
/// release is signed by the prover's own key but self-attested: the schedule
/// removes honest but outdated provers, and a false claim gains a prover
/// nothing an eligible member does not have. Callers keep a shard's current
/// session when no member remains. Committee eligibility, splits, merges and
/// reassignment do not apply the gate.
pub fn desired_members(scan: &CommittedProverScan, filter: &[u8], frame: u64) -> Vec<Vec<u8>> {
    use super::super::prover_release::{minimum_release_at, seat_eligible};
    if minimum_release_at(frame).is_none() {
        return members_where(scan, filter, frame, |_| true);
    }
    let releases = scan.releases_on_filter(filter);
    members_where(scan, filter, frame, |address| seat_eligible(releases.get(address), frame))
}

/// [`desired_members`] without the release gate: the committee a merge's
/// successor takes, which, like a split's, seats every eligible prover of its
/// sources. A merge whose successor would have no member is dropped, unlike
/// a membership change, which keeps the current session; the next membership
/// boundary applies the gate to the merged shard.
fn merge_members(scan: &CommittedProverScan, filter: &[u8], frame: u64) -> Vec<Vec<u8>> {
    members_where(scan, filter, frame, |_| true)
}

fn members_where(
    scan: &CommittedProverScan,
    filter: &[u8],
    frame: u64,
    seat: impl Fn(&[u8]) -> bool,
) -> Vec<Vec<u8>> {
    let mut members: Vec<Vec<u8>> = scan
        .active_on_filter(filter, frame)
        .into_iter()
        .filter(|(_, address)| seat(address))
        .map(|(public_key, _)| public_key)
        .filter(|key| FalconPublicKey::from_bytes(key).is_some())
        .collect();
    members.sort();
    members.dedup();
    members
}

/// The children a split's provers move to, by the SAME rule as
/// `GlobalIntrinsic::reassign_shard_allocations`, so the authorized successor
/// committees match the allocations staged when the change applies.
pub fn split_assignment(
    scan: &CommittedProverScan,
    change: &PendingShardChange,
    frame: u64,
    even: bool,
) -> Vec<Vec<Vec<u8>>> {
    split_assignment_sized(scan, change, frame, even, &|_| 0)
}

/// [`split_assignment`] with each child's reward basis (`size`, its state
/// size now). Under the seniority ring rule the most senior provers move
/// together onto the most valuable child (`prover_rings::split_groups`).
pub fn split_assignment_sized(
    scan: &CommittedProverScan,
    change: &PendingShardChange,
    frame: u64,
    even: bool,
    size: &dyn Fn(&[u8]) -> u128,
) -> Vec<Vec<Vec<u8>>> {
    let k = change.children.len();
    let mut children = vec![Vec::new(); k];
    if k == 0 {
        return children;
    }
    if super::super::prover_rings::governs(frame) {
        let provers: Vec<(Vec<u8>, Vec<u8>)> = scan
            .active_on_filter(&change.parent, frame)
            .into_iter()
            .filter(|(public_key, _)| FalconPublicKey::from_bytes(public_key).is_some())
            .collect();
        let keyed: Vec<(Vec<u8>, &[u8], super::super::prover_rings::RingKey)> = provers
            .iter()
            .map(|(public_key, address)| {
                let key = scan.ring_key(address, &change.parent).unwrap_or(
                    super::super::prover_rings::RingKey { cohort: u64::MAX, seniority: 0 },
                );
                (public_key.clone(), address.as_slice(), key)
            })
            .collect();
        let order = super::super::prover_rings::children_by_value(&change.children, size);
        let Ok(groups) = super::super::prover_rings::split_groups(keyed, k) else { return children };
        for (group, index) in groups.into_iter().zip(order) {
            children[index] = group;
        }
        for members in &mut children {
            members.sort();
            members.dedup();
        }
        return children;
    }
    let mut provers = scan.active_on_filter(&change.parent, frame);
    if even {
        provers.sort_by(|a, b| a.1.cmp(&b.1));
    }
    for (i, (public_key, address)) in provers.into_iter().enumerate() {
        let index = if even {
            i % k
        } else {
            super::super::reassignment::assign_child_index(&address, k)
        };
        if FalconPublicKey::from_bytes(&public_key).is_some() {
            children[index].push(public_key);
        }
    }
    for members in &mut children {
        members.sort();
        members.dedup();
    }
    children
}

fn topology_key(change: &PendingShardChange) -> Vec<u8> {
    let mut key = vec![match change.kind {
        ShardChangeKind::Split => 1,
        ShardChangeKind::Merge => 2,
    }];
    key.extend_from_slice(&change.effective_epoch.to_be_bytes());
    key.extend_from_slice(&change.proposed_frame.to_be_bytes());
    key.extend_from_slice(&change.parent);
    key
}

fn request_id(bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| QuilError::Store("corrupt handoff scheduling record".into()))
}

/// The request that named `filter` as a target, if any. A first session that
/// the membership reconciler created has none.
pub fn activating_request(state: &impl Records, filter: &[u8]) -> Result<Option<super::Request>> {
    let Some(bytes) = read(state, b"reserved", filter)? else {
        return Ok(None);
    };
    super::request(state, &request_id(bytes)?)
}

/// A filter named as the target of a request that has not activated. It has no
/// head yet, so neither initialization nor another request may claim it:
/// activation would otherwise fail its "target changed" check forever.
pub(super) fn reserved(state: &impl Records, filter: &[u8]) -> Result<bool> {
    let Some(bytes) = read(state, b"reserved", filter)? else {
        return Ok(false);
    };
    Ok(read(state, b"activated", &request_id(bytes)?)?.is_none())
}

pub(super) fn reserve(
    state: &HypergraphState,
    frame: u64,
    targets: &[DesiredCommittee],
    request: &[u8; 32],
) -> Result<()> {
    for target in targets {
        write(state, frame, b"reserved", &target.filter, request)?;
    }
    Ok(())
}

/// Whether the transition recorded for this request has been authorized.
pub fn activated(state: &impl Records, request: &[u8; 32]) -> Result<bool> {
    Ok(read(state, b"activated", request)?.is_some())
}

/// The request a closing session must seal, for the app runtime's parent reader.
pub fn closing_request(state: &impl Records, session: &Session) -> Result<Option<[u8; 32]>> {
    Ok(match status(state, &session.id()?)? {
        Status::Active => None,
        Status::Sealing(request) => Some(request),
        Status::Closed(_) => {
            return Err(QuilError::ExecutionUnavailable(
                "committee session is retired".into(),
            ))
        }
    })
}

/// Whether this closing session's terminal certificate reached GLOBAL state.
pub fn seal_submitted(state: &impl Records, session: &Session) -> Result<bool> {
    Ok(super::submitted_checkpoint(state, &session.id()?)?.is_some())
}

/// The 32-byte output whose identity is `session.genesis`: the first data
/// frame's header names it as its predecessor. Trusted initialization uses the
/// application's empty genesis; a successor's value is stored at activation.
pub fn genesis_output(state: &impl Records, session: &Session) -> Result<Vec<u8>> {
    let output = read(state, b"genesis-output", &session.id()?)?.unwrap_or_else(|| vec![0; 32]);
    if output.len() != 32 || quil_crypto::poseidon::hash_bytes_to_32(&output)? != session.genesis {
        return Err(QuilError::Store("session genesis output does not match its identity".into()));
    }
    Ok(output)
}

/// The shards `change` removes from the grid and the shards it registers: the
/// REAL topology, as `apply_due_shard_changes` will register it. A deep split
/// replaces the parent by its two leaves AND the co-path spine, and a merge
/// removes exactly the shards it names; only that complete set covers the same
/// address range on both sides.
fn change_topology(change: &PendingShardChange) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>)> {
    let bit_path_mode = change.proposed_frame >= super::super::materialize::unified_tree_cutover_frame();
    let bits = |filter: &[u8]| quil_forest::decode_shard_filter_or_root(filter, 32).map(|(_, bits)| bits);
    Ok(match change.kind {
        ShardChangeKind::Split => {
            let output = super::super::materialize::materialize_shard_split(
                &change.parent, &change.children, bit_path_mode)?;
            let registered = output.new_shards.iter()
                .map(|(l2, path)| quil_forest::shard_prefix_to_filter(l2, path));
            // Allocations move to `change.children` byte for byte; keep that
            // spelling for the shards they name.
            let new = registered.map(|filter| {
                change.children.iter().find(|child| bits(child) == bits(&filter)).cloned().unwrap_or(filter)
            }).collect();
            (vec![change.parent.clone()], new)
        }
        ShardChangeKind::Merge => {
            let output = super::super::materialize::materialize_shard_merge(
                &change.children, &change.parent, bit_path_mode)?;
            let old = output.removed_shards.iter()
                .map(|(l2, path)| quil_forest::shard_prefix_to_filter(l2, path))
                .map(|filter| {
                    change.children.iter().find(|child| bits(child) == bits(&filter)).cloned().unwrap_or(filter)
                }).collect();
            (old, vec![change.parent.clone()])
        }
    })
}

/// Decide whether a due split/merge may apply, scheduling its source sessions
/// to close on first sight. `even` selects the post-cutover round-robin split
/// assignment, exactly as the reassignment does.
///
/// `scan` is `None` on a node that keeps a local shard grid but does not
/// materialize global state (a regular). Such a node never schedules: it holds
/// a governed change until the request and its activation arrive with its
/// synced GLOBAL state, so its grid cannot flip ahead of the archives'. (A live
/// run showed the alternative: regulars flipped at E+2, read the parent as
/// split away, and left the very committee that still had to seal.)
pub fn gate_topology_change(
    state: &HypergraphState,
    frame: u64,
    policy: &CommitteeHandoffPolicy,
    change: &PendingShardChange,
    scan: Option<&CommittedProverScan>,
    even: bool,
) -> Result<TopologyGate> {
    let ready = scan.map(|scan| move || Ok(scan));
    gate_topology_change_sized(state, frame, policy, change, ready.as_ref().map(|f| f as _), even, &|_| 0)
}

/// [`gate_topology_change`] with each split child's reward basis (`size`),
/// which orders the children a split's provers move to. `scan` builds the
/// committed prover scan, and is called only once the change gets past the
/// record and session checks: the scan reads all of GLOBAL's committed provers,
/// and a change waiting on its sources is due, and gated, on every frame.
pub fn gate_topology_change_sized<'s>(
    state: &HypergraphState,
    frame: u64,
    policy: &CommitteeHandoffPolicy,
    change: &PendingShardChange,
    scan: Option<&dyn Fn() -> Result<&'s CommittedProverScan>>,
    even: bool,
    size: &dyn Fn(&[u8]) -> u128,
) -> Result<TopologyGate> {
    if frame < policy.activation_frame {
        return Ok(TopologyGate::Apply);
    }
    let key = topology_key(change);
    if read(state, b"dropped", &key)?.is_some() {
        return Ok(TopologyGate::Drop);
    }
    if let Some(bytes) = read(state, b"topology", &key)? {
        return Ok(if activated(state, &request_id(bytes)?)? {
            TopologyGate::Apply
        } else {
            TopologyGate::Wait
        });
    }
    let (old, new) = change_topology(change)?;
    let mut sources = Vec::new();
    let mut vacant = Vec::new();
    for filter in old {
        if head(state, &filter)?.is_some() {
            sources.push(filter);
        } else if reserved(state, &filter)? || super::legacy::pending(state, &filter)? {
            // A successor of an earlier transition that has not started yet, or
            // legacy history that seals through generation zero first.
            return Ok(TopologyGate::Wait);
        } else {
            vacant.push(filter);
        }
    }
    if sources.is_empty() {
        // No committee ever formed here: there is no consensus history to seal.
        return Ok(TopologyGate::Apply);
    }
    let Some(scan) = scan else {
        return Ok(TopologyGate::Wait);
    };
    for filter in &sources {
        let session = head(state, filter)?.expect("collected above");
        if status(state, &session.id()?)? != Status::Active {
            // Closing for a membership request; retry once its successor is live.
            return Ok(TopologyGate::Wait);
        }
    }
    let scan = scan()?;
    let targets: Vec<DesiredCommittee> = match change.kind {
        ShardChangeKind::Split => {
            let assigned = split_assignment_sized(scan, change, frame, even, size);
            new.into_iter().map(|filter| {
                let members = change.children.iter().position(|child| *child == filter)
                    .map(|index| assigned[index].clone()).unwrap_or_default();
                DesiredCommittee { filter, members }
            }).collect()
        }
        ShardChangeKind::Merge => {
            let mut members: Vec<Vec<u8>> = sources.iter()
                .flat_map(|source| merge_members(scan, source, frame)).collect();
            members.sort();
            members.dedup();
            new.into_iter().map(|filter| DesiredCommittee { filter, members: members.clone() }).collect()
        }
    };
    if targets.iter().all(|target| target.members.is_empty()) {
        // Holding would keep the record due forever: a split whose provers
        // have all left would never find members.
        write(state, frame, b"dropped", &key, &[1])?;
        tracing::warn!(frame, parent = hex::encode(&change.parent), kind = ?change.kind,
            "committee handoff: no successor shard would have members; dropping the change");
        return Ok(TopologyGate::Drop);
    }
    for target in &targets {
        if !sources.contains(&target.filter) && reserved(state, &target.filter)? {
            return Ok(TopologyGate::Wait);
        }
    }
    let request = super::schedule_with_vacant(state, frame, sources, vacant, targets.clone())?;
    let id = request.id()?;
    reserve(state, frame, &targets, &id)?;
    write(state, frame, b"topology", &key, &id)?;
    tracing::info!(
        frame,
        parent = hex::encode(&change.parent),
        kind = ?change.kind,
        request = hex::encode(id),
        targets = targets.len(),
        "committee handoff: topology change waits for its source seals"
    );
    Ok(TopologyGate::Wait)
}

/// The committees a topology change's request authorized, once scheduled:
/// the split's or merge's allocations follow them when the change applies.
pub fn topology_targets(state: &impl Records, change: &PendingShardChange) -> Result<Option<Vec<DesiredCommittee>>> {
    let Some(bytes) = read(state, b"topology", &topology_key(change))? else { return Ok(None) };
    let id = request_id(bytes)?;
    Ok(super::request(state, &id)?.map(|request| {
        request.targets.into_iter().map(|target| target.committee).collect()
    }))
}

/// The request a scheduled topology change waits for, once scheduled.
pub fn topology_request(state: &impl Records, change: &PendingShardChange) -> Result<Option<[u8; 32]>> {
    read(state, b"topology", &topology_key(change))?.map(request_id).transpose()
}

/// The request `filter`'s head session is closing, or has closed, for: `None`
/// when the shard has no session or its session is active.
pub fn retiring_request(state: &impl Records, filter: &[u8]) -> Result<Option<[u8; 32]>> {
    let Some(bytes) = read(state, b"head", filter)? else { return Ok(None) };
    Ok(match status(state, &request_id(bytes)?)? {
        Status::Active => None,
        Status::Sealing(request) | Status::Closed(request) => Some(request),
    })
}

static RECOVERY_EXAMINATIONS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many requests [`recover_topology_change`] has examined in this process
/// (each examination may search up to [`RECOVERY_SEARCH_EPOCHS`] epochs of
/// topology records), for tests and diagnostics.
pub fn recovery_examinations() -> u64 {
    RECOVERY_EXAMINATIONS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Epochs searched, back from the epoch a lost change came due in, for the
/// frame that proposed it ([`recover_topology_change`]).
pub const RECOVERY_SEARCH_EPOCHS: u64 = 16;

/// The frames before which [`recover_topology_change`] rebuilds nothing: a
/// request scheduled before `request_frame` or a change proposed before
/// `proposed_frame` (the last grid reset, which dropped pending changes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryFloor {
    pub request_frame: u64,
    pub proposed_frame: u64,
}

/// What committed state says about a request one of whose sources is still
/// in the local grid with no pending change of the request naming it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recovery {
    /// The split or merge the request was scheduled for, rebuilt from the
    /// request and verified against its committed `topology` record.
    Restore(PendingShardChange),
    /// A source left the local grid, its head moved on, a later request named
    /// it as a target, the grid holds a shard the change registers or one
    /// overlapping a source, or a staffed target was split or merged away:
    /// the change was applied here, and a later one may have registered the
    /// shard again. Names the guard that decided.
    Applied(&'static str),
    /// Not a split or merge this repair restores (a membership request, or
    /// one before the floor), now or on any later frame.
    Never,
    /// A split or merge whose change cannot be rebuilt unambiguously; this
    /// does not change on later frames.
    Unresolved(&'static str),
}

/// Rebuild the split or merge request `id` was scheduled for, for a node whose
/// local store lost the pending record (a store rewritten or restored outside
/// execution, say) while the request reached it with committed state.
///
/// A request is written only from a live pending change (the gate above), and
/// that change is consumed only when its flip removes the request's sources
/// from the grid. A source still in the grid, still headed by the request's
/// source session, and named as a target by no later request, therefore means
/// the change has not applied here, and the network's archives still hold it
/// (or applied it at the same gate this node will now pass).
///
/// The request keeps everything but the change's proposal frame and effective
/// epoch, which `topology_key` needs: the proposal frame is searched over the
/// [`RECOVERY_SEARCH_EPOCHS`] epochs before the request's due epoch, and the
/// rebuilt change is accepted only if its committed `topology` record names
/// `id`. A split's children are the targets with members: the gate gives every
/// member to a child, and a child goes without members only when the parent
/// had fewer provers than children, which then leaves every other child with
/// at most one; that case is ambiguous with the spine and is not rebuilt.
///
/// `in_grid` says whether the local grid holds a shard, and `overlapped`
/// whether it holds another shard covering part of a shard's range (an
/// ancestor or a descendant). A shard the request authorized with members,
/// or one overlapping a source, in the grid means the change applied here and
/// a later change re-registered a source: a merge whose ranges had no
/// committee needs no request, so it can bring a split's parent back beside
/// the split's children. So does a staffed target whose head is closing or
/// closed for a request that does not name it as a target: a later split or
/// merge took it away, and a chain of such changes may have brought a source
/// back by ungoverned ones. The price is that a store which lost the change
/// and whose children the network has since split or merged away is not
/// rebuilt. A merge's children come back sorted; the caller restores the
/// proposal's order.
pub fn recover_topology_change(
    state: &impl Records,
    id: &[u8; 32],
    floor: RecoveryFloor,
    in_grid: &dyn Fn(&[u8]) -> bool,
    overlapped: &dyn Fn(&[u8]) -> bool,
) -> Result<Recovery> {
    RECOVERY_EXAMINATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let Some(scheduled) = request(state, id)? else {
        return Ok(Recovery::Unresolved("the request record is absent"));
    };
    if scheduled.frame < floor.request_frame {
        return Ok(Recovery::Never);
    }
    let sources: Vec<Vec<u8>> = scheduled.sources.iter().map(|source| source.filter.clone()).collect();
    let targets: Vec<Vec<u8>> = scheduled.targets.iter().map(|target| target.committee.filter.clone()).collect();
    let split = sources.len() == 1
        && scheduled.vacant.is_empty()
        && targets.len() >= 2
        && !targets.contains(&sources[0]);
    let merge = targets.len() == 1
        && sources.len() + scheduled.vacant.len() >= 2
        && !sources.contains(&targets[0])
        && !scheduled.vacant.contains(&targets[0]);
    if !split && !merge {
        return Ok(Recovery::Never);
    }
    // The change applied here if any of these holds, and a later change then
    // registered a source again. They run before every unresolved verdict, so
    // a healthy store never reports one.
    // - Before its flip, a prefix-free grid that holds the sources holds none
    //   of the shards the flip registers, and nothing else in their ranges.
    if scheduled.targets.iter().any(|target| !target.committee.members.is_empty() && in_grid(&target.committee.filter)) {
        return Ok(Recovery::Applied("a shard the change registers is in the grid"));
    }
    if scheduled.sources.iter().any(|source| overlapped(&source.filter)) {
        return Ok(Recovery::Applied("a shard overlapping a source is in the grid"));
    }
    // - Once the request activated, a staffed target's session came from it.
    //   Until the flip the target is outside the grid and nothing closes it
    //   but a membership successor, so a head closing or closed for a request
    //   that does not name it as a target means a later split or merge took
    //   it away. (Before activation the request reserves its targets, and a
    //   target's head is an older session that earlier changes may have
    //   closed.)
    if activated(state, id)? {
        for target in scheduled.targets.iter().filter(|target| !target.committee.members.is_empty()) {
            let Some(closing) = retiring_request(state, &target.committee.filter)? else { continue };
            let named = request(state, &closing)?.is_some_and(|later| {
                later.targets.iter().any(|next| next.committee.filter == target.committee.filter)
            });
            if !named {
                return Ok(Recovery::Applied("a staffed target was split or merged away"));
            }
        }
    }
    // - Every source is in the grid, headed by its source session, and named
    //   as a target by no later request.
    for source in &scheduled.sources {
        if !in_grid(&source.filter) {
            return Ok(Recovery::Applied("a source is not in the grid"));
        }
        let Some(bytes) = read(state, b"head", &source.filter)? else {
            return Ok(Recovery::Applied("a source has no head"));
        };
        if request_id(bytes)? != source.id()? {
            return Ok(Recovery::Applied("a source's head moved on"));
        }
        if let Some(bytes) = read(state, b"reserved", &source.filter)? {
            let later = request(state, &request_id(bytes)?)?.map_or(true, |named| named.frame >= scheduled.frame);
            if later {
                return Ok(Recovery::Applied("a later request names a source as a target"));
            }
        }
    }
    let (kind, parent, mut children) = if split {
        let crowded = scheduled.targets.iter().any(|target| target.committee.members.len() >= 2);
        let unmanned = scheduled.targets.iter().any(|target| target.committee.members.is_empty());
        if unmanned && !crowded {
            return Ok(Recovery::Unresolved("a split child may have received no members"));
        }
        let children: Vec<Vec<u8>> = scheduled.targets.iter()
            .filter(|target| !target.committee.members.is_empty())
            .map(|target| target.committee.filter.clone())
            .collect();
        if children.len() > 8 {
            return Ok(Recovery::Unresolved("a split names more than eight children"));
        }
        (ShardChangeKind::Split, sources[0].clone(), children)
    } else {
        let mut children = sources.clone();
        children.extend(scheduled.vacant.iter().cloned());
        (ShardChangeKind::Merge, targets[0].clone(), children)
    };
    children.sort();
    let mut shards: Vec<_> = children.iter()
        .map(|child| quil_forest::decode_shard_filter_or_root(child, 32))
        .collect();
    shards.sort();
    shards.dedup();
    if children.len() < 2 || shards.len() != children.len() || shards.iter().any(Option::is_none) {
        return Ok(Recovery::Unresolved("the children cannot be identified"));
    }
    let cutover = super::super::materialize::unified_tree_cutover_frame();
    let first_frame = floor.proposed_frame.max(cutover);
    let mut change = PendingShardChange { kind, parent, children, effective_epoch: 0, proposed_frame: first_frame };
    let sorted = |mut filters: Vec<Vec<u8>>| { filters.sort(); filters };
    let (old, new) = match change_topology(&change) {
        Ok((old, new)) => (sorted(old), sorted(new)),
        Err(QuilError::InvalidArgument(_)) => return Ok(Recovery::Unresolved("the rebuilt change does not materialize")),
        Err(error) => return Err(error),
    };
    let expected = match kind {
        ShardChangeKind::Split => (vec![change.parent.clone()], sorted(targets)),
        ShardChangeKind::Merge => (change.children.clone(), vec![change.parent.clone()]),
    };
    if (old, new) != expected {
        return Ok(Recovery::Unresolved("the rebuilt change does not cover the request's shards"));
    }
    // Due at the request's frame: proposed two or more epochs before it.
    let length = quil_types::consensus::epoch_length_frames();
    let Some(proposal_epoch) = quil_types::consensus::epoch_for_frame(scheduled.frame).checked_sub(2) else {
        return Ok(Recovery::Never);
    };
    let last = (proposal_epoch + 1) * length - 1;
    let first = (proposal_epoch.saturating_sub(RECOVERY_SEARCH_EPOCHS - 1) * length).max(first_frame);
    if last < first {
        return Ok(Recovery::Never);
    }
    for frame in (first..=last).rev() {
        change.proposed_frame = frame;
        change.effective_epoch = quil_types::consensus::epoch_for_frame(frame) + 2;
        let key = topology_key(&change);
        if read(state, b"topology", &key)?.as_deref() == Some(id.as_slice()) {
            if read(state, b"dropped", &key)?.is_some() {
                return Ok(Recovery::Never);
            }
            return Ok(Recovery::Restore(change));
        }
    }
    Ok(Recovery::Unresolved("no topology record of the searched proposal frames names the request"))
}

/// Epochs a closing session may take to seal before GLOBAL fences it.
pub const FENCE_AFTER_EPOCHS: u64 = 4;

/// Epochs a closing session requested at or after
/// [`super::early_fence_frame`] may take to seal before GLOBAL fences it.
pub const EARLY_FENCE_AFTER_EPOCHS: u64 = 1;

/// Epochs a closing session whose request GLOBAL made at `request_frame` may
/// take to seal before GLOBAL fences it. The request's committed frame
/// selects the rule, so a request's timeout never changes once it is made.
pub fn fence_after_epochs(request_frame: u64) -> u64 {
    if request_frame >= super::early_fence_frame() {
        EARLY_FENCE_AFTER_EPOCHS
    } else {
        FENCE_AFTER_EPOCHS
    }
}

/// The first GLOBAL frame at which [`fence_stalled_sources`] fences a
/// closing session whose request GLOBAL made at `request_frame` and which has
/// not sealed. Members date a fence by it too (the engine's fence rewind),
/// so they and GLOBAL agree on it.
pub fn fence_due_frame(request_frame: u64) -> u64 {
    request_frame.saturating_add(
        fence_after_epochs(request_frame).saturating_mul(quil_types::consensus::epoch_length_frames()),
    )
}

/// Fence every closing source among `filters`' head sessions whose request is
/// [`fence_after_epochs`] epochs old ([`fence_due_frame`]) and which has not
/// sealed, then authorize the successors of any request that thereby has
/// every source ended. Reads committed state only, so every materializing
/// node fences the same sessions. Returns how many sessions were fenced.
///
/// The fence is the session's executed tip: its frame, view and digest, with
/// zero state and history roots (nothing certifies the state after the tip).
/// A session GLOBAL never executed a frame of has no tip and is fenced at its
/// base. When it succeeded a same-filter predecessor its state is that
/// predecessor's checkpoint, and the fence carries the predecessor's certified
/// roots. Otherwise (a first session, or the child of a split or merge) no
/// roots of its own state are certified and the fence carries none: its
/// successor's members take the state from an archive and authenticate it
/// against the session's origins where those were sealed. Leaving such a
/// session closing would strand its shard for good.
///
/// From [`super::fenced_successor_eligibility_frame`], a membership
/// successor the fence authorizes takes `eligible`'s committee for its shard
/// (the committed eligibility the same pass reconciles against), not the one
/// its request fixed when it was scheduled ([`fenced_committee`]).
pub fn fence_stalled_sources(
    state: &HypergraphState,
    frame: u64,
    filters: &[Vec<u8>],
    mut eligible: Option<&mut dyn FnMut(&[u8]) -> Result<Vec<Vec<u8>>>>,
) -> Result<usize> {
    let mut fenced = 0;
    for filter in filters {
        let Some(session) = head(state, filter)? else { continue };
        let id = session.id()?;
        let Status::Sealing(request_id) = status(state, &id)? else { continue };
        let key = seal_key(&request_id, &id);
        if read(state, b"seal", &key)?.is_some() || read(state, b"fence", &key)?.is_some() {
            continue;
        }
        let pending = request(state, &request_id)?
            .ok_or_else(|| QuilError::Store("closing session's request is absent".into()))?;
        if frame < fence_due_frame(pending.frame) {
            continue;
        }
        let checkpoint = write_fence(state, frame, filter, &session, &id, &request_id)?;
        tracing::warn!(
            frame,
            filter = hex::encode(filter),
            generation = session.generation,
            fenced_at = checkpoint.frame,
            request = hex::encode(request_id),
            after_epochs = fence_after_epochs(pending.frame),
            "committee handoff: closing session did not seal in time; fenced at its executed tip"
        );
        fenced += 1;
        let members = match eligible.as_deref_mut() {
            Some(eligible) if frame >= super::fenced_successor_eligibility_frame() => {
                fenced_committee(&pending, eligible)?
            }
            _ => None,
        };
        if activate_with(state, frame, &pending, members)? {
            tracing::info!(frame, request = hex::encode(request_id),
                "committee handoff: successors authorized from fenced sources");
        }
    }
    Ok(fenced)
}

/// Record GLOBAL's fence of `session` (ID `id`) of `filter`, closing for
/// request `request_id`, and return its checkpoint: the session's executed
/// tip, or its base without one ([`fence_stalled_sources`]).
fn write_fence(
    state: &HypergraphState,
    frame: u64,
    filter: &[u8],
    session: &Session,
    id: &[u8; 32],
    request_id: &[u8; 32],
) -> Result<quil_cw_consensus::handoff::Checkpoint> {
    let checkpoint = match session_tip(state, id)? {
        // A tip header certifies its frame's identity and its PRE-state
        // roots (after the frame before it); nothing certifies the state
        // after it. The fence names the frame and leaves the roots zero;
        // the successor committee's first header attests them, since each
        // of its voters checks that header's pre-state against its own.
        Some(tip) => quil_cw_consensus::handoff::Checkpoint { state_roots: [[0; 32]; 4], ..tip },
        None => {
            let predecessor = origins(state, id)?
                .into_iter()
                .find(|(source, checkpoint)| source.filter == session.filter && checkpoint.frame == session.base_frame);
            let state_roots = match predecessor {
                Some((_, origin)) => origin.state_roots,
                None => {
                    tracing::warn!(frame, filter = hex::encode(filter), generation = session.generation,
                        "committee handoff: stalled session has no executed frame and no same-filter \
                         predecessor; fenced at its base without certified roots");
                    [[0; 32]; 4]
                }
            };
            quil_cw_consensus::handoff::Checkpoint {
                frame: session.base_frame,
                view: 0,
                digest: session.genesis,
                state_roots,
                history_root: [0; 32],
            }
        }
    };
    let checkpoint = quil_cw_consensus::handoff::Checkpoint { history_root: [0; 32], ..checkpoint };
    let mut bytes = Vec::new();
    checkpoint.write(&mut bytes);
    write(state, frame, b"fence", &seal_key(request_id, id), &bytes)?;
    Ok(checkpoint)
}

/// Kind of the record of the GLOBAL frame an early fence ([`fence_absent`])
/// was written at, keyed like the fence.
const FENCE_FRAME: &[u8] = b"fence-frame";

/// The GLOBAL frame GLOBAL fenced closing session `id` at, or will fence it
/// at if it does not seal: the frame recorded for an early fence
/// ([`fence_absent`]), else [`fence_due_frame`] of its closing request.
/// `None` for an active session or one whose request is absent. App provers
/// date a fence by it when they rewind past one.
pub fn fence_frame(state: &impl Records, id: &[u8; 32]) -> Result<Option<u64>> {
    let request_id = match status(state, id)? {
        Status::Active => return Ok(None),
        Status::Sealing(request_id) | Status::Closed(request_id) => request_id,
    };
    if let Some(bytes) = read(state, FENCE_FRAME, &seal_key(&request_id, id))? {
        let frame = <[u8; 8]>::try_from(bytes.as_slice())
            .map_err(|_| QuilError::Store("corrupt early fence frame".into()))?;
        return Ok(Some(u64::from_be_bytes(frame)));
    }
    Ok(request(state, &request_id)?.map(|request| fence_due_frame(request.frame)))
}

/// Whether `request` is a membership change of `filter`: its one source and
/// its one target are that shard.
pub(super) fn membership_request(request: &super::Request, filter: &[u8]) -> bool {
    match (request.sources.as_slice(), request.targets.as_slice()) {
        ([source], [target]) => {
            source.filter == filter && target.committee.filter == filter && request.vacant.is_empty()
        }
        _ => false,
    }
}

/// Fence early each stalled session [`super::exclusion::evaluate`] decided
/// to exclude absent members of, authorize its successor with the
/// decision's committee, and only then record the exclusions: the session
/// cannot seal below its quorum, and its present members reach the
/// successor's. An active session is first asked to close for that
/// committee; a closing one's request committee is replaced by it. The
/// fence is the session's executed tip, as at its timeout
/// ([`fence_stalled_sources`]); its GLOBAL frame is recorded
/// ([`fence_frame`]). Runs before due fences and the membership pass, which
/// then seat eligibility less the new exclusions. A session already ended,
/// succeeded, closing for a split or merge, or whose shard a pending split
/// or merge reserves is left alone, and nobody is excluded. Returns how many
/// sessions were fenced. A decision refused by a rule (an `InvalidArgument`
/// error) is undone whole and logged, and the others stand; any other error
/// (a store failure) fails the whole frame, on every node alike.
pub fn fence_absent(state: &HypergraphState, frame: u64, decisions: &[super::exclusion::Decision]) -> Result<usize> {
    let mut fenced = 0;
    for decision in decisions {
        let checkpoint = state.changeset_len();
        match fence_absent_session(state, frame, decision) {
            Ok(true) => fenced += 1,
            Ok(false) => {}
            Err(error) if matches!(error, QuilError::InvalidArgument(_)) => {
                state.rollback_to(checkpoint);
                tracing::error!(frame, filter = hex::encode(&decision.filter), %error,
                    "committee presence: early fence of a stalled session failed; it waits for its timeout");
            }
            Err(error) => return Err(error),
        }
    }
    Ok(fenced)
}

fn fence_absent_session(state: &HypergraphState, frame: u64, decision: &super::exclusion::Decision) -> Result<bool> {
    let filter = &decision.filter;
    let Some(session) = head(state, filter)? else { return Ok(false) };
    let id = session.id()?;
    if id != decision.session {
        return Ok(false);
    }
    let request_id = match status(state, &id)? {
        Status::Sealing(request_id) => request_id,
        Status::Active => {
            // A split or merge that named this shard as a target and has not
            // activated would fail its activation forever once the shard
            // has another session: leave it to that change.
            if reserved(state, filter)? {
                tracing::info!(frame, filter = hex::encode(filter), generation = session.generation,
                    "committee presence: stalled session's shard is reserved by a pending split or merge; no early fence");
                return Ok(false);
            }
            let targets = vec![DesiredCommittee { filter: filter.clone(), members: decision.committee.clone() }];
            let request = schedule(state, frame, vec![filter.clone()], targets.clone())?;
            let request_id = request.id()?;
            reserve(state, frame, &targets, &request_id)?;
            request_id
        }
        Status::Closed(_) => return Ok(false),
    };
    let key = seal_key(&request_id, &id);
    if read(state, b"seal", &key)?.is_some() || read(state, b"fence", &key)?.is_some() {
        return Ok(false);
    }
    let pending = request(state, &request_id)?
        .ok_or_else(|| QuilError::Store("closing session's request is absent".into()))?;
    if !membership_request(&pending, filter) {
        return Ok(false);
    }
    let target = &pending.targets[0];
    let members = (decision.committee != target.committee.members).then(|| decision.committee.clone());
    if let Some(members) = &members {
        Session {
            chain_id: session.chain_id,
            filter: filter.clone(),
            generation: target.generation,
            genesis: [0; 32],
            base_frame: 0,
            authorization: [0; 32],
            members: members.clone(),
        }
        .validate()?;
    }
    let checkpoint = write_fence(state, frame, filter, &session, &id, &request_id)?;
    write(state, frame, FENCE_FRAME, &key, &frame.to_be_bytes())?;
    if !activate_with(state, frame, &pending, members)? {
        return Err(invalid("the early fence authorized no successor"));
    }
    for (member, next) in decision.excluded.iter().zip(&decision.strikes) {
        super::exclusion::set_exclusion(state, frame, filter, member, next)?;
    }
    tracing::warn!(
        frame,
        filter = hex::encode(filter),
        generation = session.generation,
        members = session.members.len(),
        fenced_at = checkpoint.frame,
        request = hex::encode(request_id),
        requested_at = pending.frame,
        committee = decision.committee.len(),
        committee_quorum = super::exclusion::quorum(decision.committee.len()),
        excluded = decision.excluded.len(),
        provers = ?decision.describe_strikes(),
        "committee presence: stalled session fenced early at its executed tip; its successor seats its present \
         members and excludes its absent ones",
    );
    tracing::info!(frame, request = hex::encode(request_id),
        "committee handoff: successors authorized from fenced sources");
    Ok(true)
}

/// The committee a fence's membership successor takes: its shard's eligible
/// provers now. Its request fixed the committee when it was scheduled,
/// [`fence_after_epochs`] epochs earlier, from provers that have since
/// mostly moved on, so it could not reach quorum; and the same pass's
/// reconciliation found it unlike current eligibility and asked it to close
/// at once (decided 2026-10-16).
/// `None` keeps the request's committee: a split's or merge's, one whose
/// shard has no valid eligible committee now, or one that still matches.
fn fenced_committee(
    request: &super::Request,
    eligible: &mut dyn FnMut(&[u8]) -> Result<Vec<Vec<u8>>>,
) -> Result<Option<Vec<Vec<u8>>>> {
    let ([source], [target]) = (request.sources.as_slice(), request.targets.as_slice()) else {
        return Ok(None);
    };
    if target.committee.filter != source.filter || !request.vacant.is_empty() {
        return Ok(None);
    }
    let members = eligible(&source.filter)?;
    let valid = Session {
        chain_id: source.chain_id,
        filter: source.filter.clone(),
        generation: target.generation,
        genesis: [0; 32],
        base_frame: 0,
        authorization: [0; 32],
        members: members.clone(),
    }
    .validate()
    .is_ok();
    Ok((valid && members != target.committee.members).then_some(members))
}

/// Create first sessions and schedule membership successors for `filters` (the
/// registered shard grid). Returns how many sessions or requests were created.
///
/// A first session starts at the application's empty genesis. A shard that
/// already holds legacy-certified history (a recorded legacy tip) is skipped:
/// it enters through generation zero (`legacy::migrate`, which runs before this
/// in the maintenance pass), never from the empty genesis.
/// GLOBAL frames between session passes (`reconcile_committee_sessions`).
pub const SESSION_PASS_FRAMES: u64 = 8;

/// Whether `frame`'s pass is the first of its epoch: from the policy's
/// `membership_boundary_frame`, the only pass that schedules membership
/// successors.
pub fn first_pass_of_epoch(frame: u64) -> bool {
    frame % quil_types::consensus::epoch_length_frames() < SESSION_PASS_FRAMES
}

pub fn reconcile_membership(
    state: &HypergraphState,
    frame: u64,
    policy: &CommitteeHandoffPolicy,
    filters: &[Vec<u8>],
    scan: &CommittedProverScan,
) -> Result<usize> {
    if frame < policy.activation_frame {
        return Ok(0);
    }
    let mut created = 0;
    for filter in filters {
        // From the presence exclusion frame, less the members excluded for
        // absence (`exclusion::seated`).
        let members = super::exclusion::seated(state, frame, filter, desired_members(scan, filter, frame))?;
        if members.is_empty() {
            continue;
        }
        let Some(current) = head(state, filter)? else {
            // Legacy history continues through generation zero (`legacy::migrate`),
            // never from the empty genesis. A shard without a recorded tip starts
            // there (`legacy::defaults::DEAD_LEGACY_SHARDS_GET_A_FRESH_SESSION`).
            if reserved(state, filter)? || super::legacy::pending(state, filter)? {
                continue;
            }
            // Like a membership change, a first session waits for the epoch's
            // first pass from `first_session_boundary_frame`.
            if frame >= policy.first_session_boundary_frame && !first_pass_of_epoch(frame) {
                continue;
            }
            let genesis = quil_crypto::poseidon::hash_bytes_to_32(&[0u8; 32])?;
            initialize(
                state,
                frame,
                &Session {
                    chain_id: policy.chain_id,
                    filter: filter.clone(),
                    generation: 1,
                    genesis,
                    base_frame: 0,
                    authorization: [0; 32],
                    members,
                },
            )?;
            tracing::info!(frame, filter = hex::encode(filter), "committee handoff: first session authorized");
            created += 1;
            continue;
        };
        if current.members == members || status(state, &current.id()?)? != Status::Active {
            continue;
        }
        // The committee is frozen for the epoch: an eligible set that changes
        // within it (a late re-confirm, a leave reject) waits for the next
        // boundary. Mid-epoch, every such change re-sealed every shard its
        // prover sat on, every pass, and no session ever produced a frame.
        if frame >= policy.membership_boundary_frame && !first_pass_of_epoch(frame) {
            continue;
        }
        if current.chain_id != policy.chain_id {
            return Err(invalid("session belongs to another chain"));
        }
        let targets = vec![DesiredCommittee {
            filter: filter.clone(),
            members,
        }];
        let request = schedule(state, frame, vec![filter.clone()], targets.clone())?;
        let id = request.id()?;
        reserve(state, frame, &targets, &id)?;
        tracing::info!(
            frame,
            filter = hex::encode(filter),
            request = hex::encode(id),
            "committee handoff: membership successor scheduled"
        );
        created += 1;
    }
    Ok(created)
}
