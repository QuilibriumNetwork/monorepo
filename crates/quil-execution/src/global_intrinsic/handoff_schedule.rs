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
//! [`FENCE_AFTER_EPOCHS`] epochs GLOBAL fences it instead
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
    activate, head, initialize, invalid, origins, read, request, schedule, seal_key, session_tip,
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
pub fn desired_members(scan: &CommittedProverScan, filter: &[u8], frame: u64) -> Vec<Vec<u8>> {
    let mut members: Vec<Vec<u8>> = scan
        .active_on_filter(filter, frame)
        .into_iter()
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
    // The REAL topology, as `apply_due_shard_changes` will register it. A deep
    // split replaces the parent by its two leaves AND the co-path spine, and a
    // merge removes exactly the shards it names; only that complete set covers
    // the same address range on both sides.
    let bit_path_mode = change.proposed_frame >= super::super::materialize::unified_tree_cutover_frame();
    let bits = |filter: &[u8]| quil_forest::decode_shard_filter_or_root(filter, 32).map(|(_, bits)| bits);
    let (old, new): (Vec<Vec<u8>>, Vec<Vec<u8>>) = match change.kind {
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
    };
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
                .flat_map(|source| desired_members(scan, source, frame)).collect();
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

/// Epochs a closing session may take to seal before GLOBAL fences it.
pub const FENCE_AFTER_EPOCHS: u64 = 4;

/// Fence every closing source among `filters`' head sessions whose request is
/// [`FENCE_AFTER_EPOCHS`] epochs old and which has not sealed, then authorize
/// the successors of any request that thereby has every source ended. Reads
/// committed state only, so every materializing node fences the same sessions.
/// Returns how many sessions were fenced.
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
pub fn fence_stalled_sources(state: &HypergraphState, frame: u64, filters: &[Vec<u8>]) -> Result<usize> {
    let timeout = FENCE_AFTER_EPOCHS.saturating_mul(quil_types::consensus::epoch_length_frames());
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
        if frame < pending.frame.saturating_add(timeout) {
            continue;
        }
        let checkpoint = match session_tip(state, &id)? {
            // A tip header certifies its frame's identity and its PRE-state
            // roots (after the frame before it); nothing certifies the state
            // after it. The fence names the frame and leaves the roots zero;
            // the successor committee's first header attests them, since each
            // of its voters checks that header's pre-state against its own.
            Some(tip) => quil_cw_consensus::handoff::Checkpoint { state_roots: [[0; 32]; 4], ..tip },
            None => {
                let predecessor = origins(state, &id)?
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
        write(state, frame, b"fence", &key, &bytes)?;
        tracing::warn!(
            frame,
            filter = hex::encode(filter),
            generation = session.generation,
            fenced_at = checkpoint.frame,
            request = hex::encode(request_id),
            "committee handoff: closing session did not seal in time; fenced at its executed tip"
        );
        fenced += 1;
        if activate(state, frame, &pending)? {
            tracing::info!(frame, request = hex::encode(request_id),
                "committee handoff: successors authorized from fenced sources");
        }
    }
    Ok(fenced)
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
        let members = desired_members(scan, filter, frame);
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
