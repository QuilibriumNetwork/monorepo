//! Seniority penalties (#976), applied by the epoch-boundary registry pass
//! of every node that executes GLOBAL frames, from committed GLOBAL state
//! only.
//!
//! Rule numbers follow the issue; rule 1 (missed turn) is not implemented.
//!
//! - Rule 2, halt-risk leave: a leave, confirmed or expired unconfirmed,
//!   whose allocation counted toward its shard costs
//!   [`HALT_RISK_LEAVE_PENALTY`] seniority at the boundary it departs, when
//!   the shard keeps at most three (`SENIORITY_PENALTY_HALT_RISK_PROVERS`)
//!   effectively-active provers.
//! - Rule 3, disappearance: GLOBAL execution counts, per allocation, the
//!   consecutive frames of its committee the member neither signed nor
//!   produced (`AbsentFrameCount`, see
//!   `prover_shard_update::record_committee_absence`) and charges each one
//!   past the grace. This pass evicts the allocations whose count reached
//!   [`ABSENCE_EVICTION_FRAMES`], at most [`EVICTION_MAX_PER_PASS`], each
//!   shard keeping its floor.
//!
//! Nothing here reads or writes state before
//! [`quil_types::consensus::seniority_penalties_at`] holds for the pass
//! frame's epoch.

use std::collections::HashMap;

use quil_types::consensus::{
    epoch_for_frame, epoch_start_frame, halt_risk_departure, seniority_penalties_at,
    EffectiveStatus, ProverStatus, ABSENCE_EVICTION_FRAMES, ABSENCE_PENALTY_GRACE_FRAMES,
    HALT_RISK_LEAVE_PENALTY, MIN_SHARD_CONSENSUS_PROVERS,
};
use quil_types::error::{QuilError, Result as QuilResult};
use quil_types::store::HypergraphStore;

use super::{
    limit_evictions_to_shard_floor, read_global_vertex_blob, rebuild_vertex_tree_from_blob,
    vertex_tree_to_blob, EvictionCandidate, InMemoryProverRegistry, SharedProverRegistry,
    EVICTION_MAX_PER_PASS,
};
use crate::global_schema::{read_field, write_field};
use crate::hypergraph_state::HypergraphState;

const ALLOCATION: &str = "allocation:ProverAllocation";

/// One halt-risk leave penalty a pass charged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeniorityPenalty {
    pub prover_address: Vec<u8>,
    pub confirmation_filter: Vec<u8>,
    /// Seniority subtracted (saturating at zero).
    pub amount: u64,
    /// The departed leave's proposal frame.
    pub leave_frame: u64,
    /// Effectively-active provers its shard kept.
    pub remaining: u64,
}

/// A leave departing at the pass's boundary, confirmed or expired unconfirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaveDeparture {
    pub prover_address: Vec<u8>,
    pub confirmation_filter: Vec<u8>,
    pub vertex_address: Vec<u8>,
    pub leave_frame: u64,
    /// Effectively-active provers left on the shard at the departure frame.
    pub remaining: u64,
}

/// What one penalty pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SeniorityPenaltyPass {
    /// Departures decided this pass, penalised or not (each once).
    pub departures: Vec<LeaveDeparture>,
    /// Halt-risk leave penalties charged.
    pub penalties: Vec<SeniorityPenalty>,
    /// Allocations evicted for absence, `effective_inactive` holding their
    /// missed committee frames.
    pub evicted: Vec<EvictionCandidate>,
}

impl SeniorityPenaltyPass {
    /// Whether the pass wrote anything.
    pub fn is_empty(&self) -> bool {
        self.departures.is_empty() && self.penalties.is_empty() && self.evicted.is_empty()
    }
}

impl InMemoryProverRegistry {
    /// Leaves departing at the boundary that begins `frame`'s epoch, confirmed
    /// or expired without a confirm
    /// ([`quil_types::consensus::ProverAllocationInfo::departure_epoch`]),
    /// whose allocation counted toward its shard when the leave was proposed
    /// ([`quil_types::consensus::ProverAllocationInfo::counted_when_leaving`]),
    /// with the shard's effectively-active provers at that boundary. A kicked
    /// prover (no prover vertex, or a prover-level kick frame) is not
    /// penalised again. Sorted by (prover, filter).
    pub(super) fn halt_risk_departures(&self, frame: u64) -> Vec<LeaveDeparture> {
        let epoch = epoch_for_frame(frame);
        let departure_frame = epoch_start_frame(epoch);
        let mut census: Option<HashMap<Vec<u8>, u64>> = None;
        let mut out = Vec::new();
        for info in self.prover_cache.values() {
            if info.status == ProverStatus::Unknown || info.kick_frame_number > 0 {
                continue;
            }
            for alloc in &info.allocations {
                if alloc.confirmation_filter.is_empty()
                    || alloc.departure_epoch() != Some(epoch)
                    || !alloc.counted_when_leaving()
                {
                    continue;
                }
                let census = census.get_or_insert_with(|| {
                    self.eviction_census(
                        departure_frame,
                        ABSENCE_PENALTY_GRACE_FRAMES,
                        &HashMap::new(),
                        quil_types::consensus::SIGNED_FRAME_ACTIVATION_FRAME,
                    )
                    .0
                });
                let Some(vertex_address) = self.allocation_vertex(
                    &info.address,
                    &alloc.confirmation_filter,
                    &alloc.vertex_address,
                ) else {
                    continue;
                };
                out.push(LeaveDeparture {
                    prover_address: info.address.clone(),
                    confirmation_filter: alloc.confirmation_filter.clone(),
                    vertex_address,
                    leave_frame: alloc.leave_frame_number,
                    remaining: census.get(&alloc.confirmation_filter).copied().unwrap_or(0),
                });
            }
        }
        out.sort_by(|a, b| {
            (&a.prover_address, &a.confirmation_filter)
                .cmp(&(&b.prover_address, &b.confirmation_filter))
        });
        out
    }

    /// Effectively-active allocations of Active provers on shards above
    /// `MIN_SHARD_CONSENSUS_PROVERS` (the only ones eviction may take), with
    /// their vertex, and every shard's effectively-active census.
    fn absence_eviction_scope(
        &self,
        frame: u64,
    ) -> (Vec<EvictionCandidate>, HashMap<Vec<u8>, u64>) {
        let (active_by_filter, _) = self.eviction_census(
            frame,
            ABSENCE_PENALTY_GRACE_FRAMES,
            &HashMap::new(),
            quil_types::consensus::SIGNED_FRAME_ACTIVATION_FRAME,
        );
        let mut scope = Vec::new();
        for info in self.prover_cache.values() {
            if info.status != ProverStatus::Active {
                continue;
            }
            for alloc in &info.allocations {
                if alloc.confirmation_filter.is_empty()
                    || alloc.effective_status(frame) != EffectiveStatus::Active
                    || active_by_filter
                        .get(&alloc.confirmation_filter)
                        .copied()
                        .unwrap_or(0)
                        <= MIN_SHARD_CONSENSUS_PROVERS
                {
                    continue;
                }
                let Some(vertex_address) = self.allocation_vertex(
                    &info.address,
                    &alloc.confirmation_filter,
                    &alloc.vertex_address,
                ) else {
                    continue;
                };
                scope.push(EvictionCandidate {
                    prover_address: info.address.clone(),
                    confirmation_filter: alloc.confirmation_filter.clone(),
                    vertex_address,
                    effective_inactive: 0,
                });
            }
        }
        scope.sort_by(|a, b| {
            (&a.prover_address, &a.confirmation_filter)
                .cmp(&(&b.prover_address, &b.confirmation_filter))
        });
        (scope, active_by_filter)
    }
}

/// Read an allocation's u64 field from `state` (or the flat store).
fn allocation_u64(
    state: &HypergraphState,
    store: Option<&dyn HypergraphStore>,
    vertex: &[u8],
    field: &str,
) -> QuilResult<Option<u64>> {
    Ok(read_global_vertex_blob(state, store, vertex)?.map(|blob| {
        read_field(&rebuild_vertex_tree_from_blob(&blob), ALLOCATION, field)
            .and_then(|b| b.get(..8).and_then(|s| s.try_into().ok()))
            .map(u64::from_be_bytes)
            .unwrap_or(0)
    }))
}

/// Write `value` to an allocation's u64 `field` in `state`.
fn write_allocation_u64(
    state: &HypergraphState,
    store: Option<&dyn HypergraphStore>,
    vertex: &[u8],
    field: &str,
    value: u64,
    frame: u64,
) -> QuilResult<()> {
    let blob = read_global_vertex_blob(state, store, vertex)?.ok_or_else(|| {
        QuilError::Internal("seniority penalty: allocation vertex not found".into())
    })?;
    let mut tree = rebuild_vertex_tree_from_blob(&blob);
    write_field(&mut tree, ALLOCATION, field, &value.to_be_bytes())?;
    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    state.set(
        &crate::domains::GLOBAL[..],
        vertex,
        &va_disc,
        frame,
        vertex_tree_to_blob(&tree),
    )
}

/// Subtract `amount` from the prover vertex's `Seniority`, saturating at
/// zero, and add what it subtracted to the prover's `SeniorityPenalty`.
/// Returns the seniority subtracted, or `None` when the prover vertex is in
/// neither the CRDT nor the flat store.
fn charge_seniority(
    state: &HypergraphState,
    store: Option<&dyn HypergraphStore>,
    prover: &[u8],
    amount: u64,
    frame: u64,
) -> QuilResult<Option<u64>> {
    let Some(blob) = read_global_vertex_blob(state, store, prover)? else {
        return Ok(None);
    };
    let mut tree = rebuild_vertex_tree_from_blob(&blob);
    let seniority = read_field(&tree, "prover:Prover", "Seniority")
        .and_then(|b| b.get(..8).and_then(|s| s.try_into().ok()))
        .map(u64::from_be_bytes)
        .unwrap_or(0);
    let charged = seniority.min(amount);
    write_field(
        &mut tree,
        "prover:Prover",
        "Seniority",
        &(seniority - charged).to_be_bytes(),
    )?;
    crate::global_intrinsic::seniority_succession::record_seniority_penalty(&mut tree, charged)?;
    let va_disc = crate::hypergraph_state::vertex_adds_discriminator()?;
    state.set(
        &crate::domains::GLOBAL[..],
        prover,
        &va_disc,
        frame,
        vertex_tree_to_blob(&tree),
    )?;
    Ok(Some(charged))
}

impl SharedProverRegistry {
    /// Apply the seniority penalties due at `frame` in `state` (see the
    /// module docs): decide each leave departing at this epoch's
    /// boundary once (`LeavePenaltyFrameNumber` records its leave frame) and
    /// charge [`HALT_RISK_LEAVE_PENALTY`] when its shard keeps at most
    /// `SENIORITY_PENALTY_HALT_RISK_PROVERS` effectively-active provers; then
    /// evict the allocations whose `AbsentFrameCount` reached
    /// [`ABSENCE_EVICTION_FRAMES`] (at most [`EVICTION_MAX_PER_PASS`], each
    /// shard keeping its floor, most absent first) and reset their count.
    ///
    /// Before the penalty epoch it returns an empty pass without reading or
    /// writing anything. Every input is committed registry state and the
    /// allocation fields; the output is sorted, so every node applies the
    /// same changes. The caller commits `state`.
    pub fn apply_seniority_penalties(
        &self,
        frame: u64,
        state: &HypergraphState,
        store: Option<&dyn HypergraphStore>,
    ) -> QuilResult<SeniorityPenaltyPass> {
        if !seniority_penalties_at(epoch_for_frame(frame)) {
            return Ok(SeniorityPenaltyPass::default());
        }
        self.check_execution_store(state.crdt().backing_store_identity())?;
        if let Some(store) = store {
            self.check_execution_store(store.backing_store_identity())?;
        }
        let (departures, (scope, active_by_filter)) = {
            let guard = self
                .inner
                .read()
                .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
            (
                guard.halt_risk_departures(frame),
                guard.absence_eviction_scope(frame),
            )
        };

        let mut pass = SeniorityPenaltyPass::default();
        for departure in departures {
            let decided = allocation_u64(
                state,
                store,
                &departure.vertex_address,
                "LeavePenaltyFrameNumber",
            )?;
            match decided {
                None => continue,
                Some(leave) if leave == departure.leave_frame => continue,
                Some(_) => {}
            }
            write_allocation_u64(
                state,
                store,
                &departure.vertex_address,
                "LeavePenaltyFrameNumber",
                departure.leave_frame,
                frame,
            )?;
            if halt_risk_departure(departure.remaining) {
                if let Some(amount) = charge_seniority(
                    state,
                    store,
                    &departure.prover_address,
                    HALT_RISK_LEAVE_PENALTY,
                    frame,
                )? {
                    crate::seniority_penalty_log::record(
                        frame,
                        crate::seniority_penalty_log::PenaltyRule::HaltRiskLeave,
                        &departure.prover_address,
                        &departure.confirmation_filter,
                        amount,
                        departure.leave_frame,
                    );
                    pass.penalties.push(SeniorityPenalty {
                        prover_address: departure.prover_address.clone(),
                        confirmation_filter: departure.confirmation_filter.clone(),
                        amount,
                        leave_frame: departure.leave_frame,
                        remaining: departure.remaining,
                    });
                }
            }
            pass.departures.push(departure);
        }

        let mut absent = Vec::new();
        for mut candidate in scope {
            let missed =
                allocation_u64(state, store, &candidate.vertex_address, "AbsentFrameCount")?
                    .unwrap_or(0);
            if missed >= ABSENCE_EVICTION_FRAMES {
                candidate.effective_inactive = missed;
                absent.push(candidate);
            }
        }
        let evict = limit_evictions_to_shard_floor(absent, &active_by_filter)
            .into_iter()
            .take(EVICTION_MAX_PER_PASS)
            .map(|candidate| {
                let vertex = Some(candidate.vertex_address.clone());
                (candidate, vertex)
            })
            .collect();
        pass.evicted = self.kick_selected(evict, frame, state, store)?;
        for evicted in &pass.evicted {
            write_allocation_u64(
                state,
                store,
                &evicted.vertex_address,
                "AbsentFrameCount",
                0,
                frame,
            )?;
            crate::seniority_penalty_log::record(
                frame,
                crate::seniority_penalty_log::PenaltyRule::Eviction,
                &evicted.prover_address,
                &evicted.confirmation_filter,
                0,
                frame,
            );
        }

        if !pass.penalties.is_empty() {
            let mut guard = self
                .inner
                .write()
                .map_err(|_| QuilError::Internal("prover registry lock poisoned".into()))?;
            self.refresh.note_edit();
            for penalty in &pass.penalties {
                if let Some(info) = guard.prover_cache.get_mut(&penalty.prover_address) {
                    info.seniority = info.seniority.saturating_sub(penalty.amount);
                }
            }
            guard.diverged = true;
        }
        Ok(pass)
    }
}
