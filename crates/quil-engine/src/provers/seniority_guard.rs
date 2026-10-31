//! Keep this node's own leaves clear of the halt-risk leave penalty (#976),
//! and tell the operator when a leave, or a charge, costs this prover
//! seniority. Inert until `MAINNET_SENIORITY_PENALTY_EPOCH`.
//!
//! Consensus charges [`HALT_RISK_LEAVE_PENALTY`] (rule 2 of #976) when a
//! leave, confirmed or left to expire, of an allocation that counted toward
//! its shard departs and leaves the shard at or below
//! `SENIORITY_PENALTY_HALT_RISK_PROVERS` effectively-active provers. The
//! lifecycle withholds every automatic leave proposal that would do so and
//! rejects such a pending leave at its confirm window rather than confirm it
//! or let it expire; an operator's manual leave goes ahead, with a notice.

use std::collections::{BTreeMap, BTreeSet};

use quil_types::consensus::{
    epoch_for_frame, halt_risk_departure, seniority_penalties_at, EffectiveStatus,
    LifecycleMembers, ProverAllocationInfo, ProverStatus, HALT_RISK_LEAVE_PENALTY,
};
use tracing::{info, warn};

/// A departure of this prover's allocation that would cost the halt-risk
/// leave penalty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PenalisedDeparture {
    /// The epoch it would depart at.
    pub departure_epoch: u64,
    /// Effectively-active provers its shard would keep.
    pub remaining: u64,
}

/// Effectively-active provers a shard keeps after `me` departs, if no other
/// undecided leave departs: its staying members, less `me` when it still
/// counts among them. A shard without members keeps none.
pub(crate) fn remaining_after_departure(members: Option<&LifecycleMembers>, me: &[u8]) -> u64 {
    let Some(members) = members else {
        return 0;
    };
    let counted = members
        .active
        .iter()
        .chain(&members.activating)
        .filter(|address| address.as_slice() == me)
        .count();
    members.staying().saturating_sub(counted) as u64
}

/// Whether `alloc`, this prover's allocation on its shard, would cost the
/// halt-risk leave penalty if it left now (an Active allocation: proposed at
/// `frame`, departing two boundaries on) or if its pending leave were
/// confirmed (a Leaving one: departing two boundaries after its proposal,
/// the confirm being due in the epoch between), given the
/// shard's `members` at `frame`. A pending leave departs at that boundary
/// whether it is confirmed or left to expire, and costs the penalty either
/// way, so the lifecycle rejects it instead. A confirmed leave is already
/// decided.
pub(crate) fn penalised_departure(
    alloc: &ProverAllocationInfo,
    frame: u64,
    members: Option<&LifecycleMembers>,
    me: &[u8],
) -> Option<PenalisedDeparture> {
    let epoch = epoch_for_frame(frame);
    let (counted, departure_epoch) = match alloc.status {
        ProverStatus::Leaving if alloc.leave_confirm_frame_number == 0 => {
            (alloc.counted_when_leaving(), alloc.departure_epoch()?)
        }
        ProverStatus::Active => (
            alloc.effective_status(frame) == EffectiveStatus::Active,
            epoch + 2,
        ),
        _ => return None,
    };
    if !counted || !seniority_penalties_at(departure_epoch) {
        return None;
    }
    let remaining = remaining_after_departure(members, me);
    halt_risk_departure(remaining).then_some(PenalisedDeparture {
        departure_epoch,
        remaining,
    })
}

/// What the lifecycle has told the operator, so each notice is logged once.
#[derive(Debug, Default)]
pub(crate) struct SeniorityGuard {
    /// Withheld automatic leaves by stage, as last logged.
    withheld: BTreeMap<&'static str, BTreeSet<Vec<u8>>>,
    /// Manual leaves (filter, leave frame) already noticed, by stage.
    noticed: BTreeSet<(&'static str, Vec<u8>, u64)>,
    /// This prover's seniority at the last evaluation, and its frame.
    seniority: Option<(u64, u64)>,
}

impl SeniorityGuard {
    /// Log the automatic leaves withheld at `stage` ("proposal" or
    /// "confirm") when the set changes. `withheld` maps each filter to its
    /// penalised departure.
    pub(crate) fn withheld(
        &mut self,
        frame: u64,
        stage: &'static str,
        withheld: &[(Vec<u8>, PenalisedDeparture)],
    ) {
        let set: BTreeSet<Vec<u8>> = withheld.iter().map(|(f, _)| f.clone()).collect();
        if self.withheld.get(stage) == Some(&set)
            || (set.is_empty() && !self.withheld.contains_key(stage))
        {
            return;
        }
        if set.is_empty() {
            self.withheld.remove(stage);
            info!(
                frame,
                stage,
                scope = "local",
                "lifecycle: no leave withheld for the halt-risk leave penalty any more"
            );
            return;
        }
        self.withheld.insert(stage, set);
        let shards: Vec<String> = withheld
            .iter()
            .map(|(f, d)| format!("{}:{}", hex::encode(f), d.remaining))
            .collect();
        info!(frame, stage, count = withheld.len(), shards = ?shards, penalty = HALT_RISK_LEAVE_PENALTY,
            scope = "local",
            action = "none: the node keeps these allocations until their shards keep more than 3 provers \
                      after it leaves; a manual leave goes ahead and costs the penalty",
            "lifecycle: withholding automatic leaves that would leave their shard at halt risk \
             and cost this prover seniority (shards as filter:remaining provers)");
    }

    /// Tell the operator once, at `stage`, that their manual leave of
    /// `filter` (proposed at `leave_frame`) costs seniority when it departs.
    pub(crate) fn manual_notice(
        &mut self,
        frame: u64,
        stage: &'static str,
        filter: &[u8],
        leave_frame: u64,
        departure: PenalisedDeparture,
    ) {
        let cur_epoch = epoch_for_frame(frame);
        self.noticed
            .retain(|(_, _, lf)| epoch_for_frame(*lf) + 3 > cur_epoch);
        if !self.noticed.insert((stage, filter.to_vec(), leave_frame)) {
            return;
        }
        info!(frame, stage, filter = %hex::encode(filter), leave_frame,
            departure_epoch = departure.departure_epoch, remaining = departure.remaining,
            penalty = HALT_RISK_LEAVE_PENALTY, scope = "local",
            action = "to keep the seniority, switch the worker to auto before its confirm: \
                      the node then rejects the leave",
            "lifecycle: a manual leave will leave its shard at halt risk; \
             consensus charges this prover the halt-risk leave penalty when it departs");
    }

    /// Warn about a fall of this prover's committed seniority since the
    /// last evaluation that no seniority penalty recorded by this node's
    /// GLOBAL execution explains (`charged_at`: the last frame one was
    /// charged to this prover; the aggregated per-epoch warning reports
    /// those). Returns whether it warned. Bounded: only a fall is reported,
    /// and the registry changes at most a few times per epoch.
    pub(crate) fn observe_seniority(
        &mut self,
        frame: u64,
        seniority: u64,
        charged_at: u64,
    ) -> bool {
        let previous = self.seniority.replace((frame, seniority));
        let Some((since, previous)) = previous else {
            return false;
        };
        if seniority >= previous
            || !seniority_penalties_at(epoch_for_frame(frame))
            || charged_at >= since
        {
            return false;
        }
        warn!(since, frame, previous, seniority, fell_by = previous - seniority, scope = "local",
            rule = "not attributable",
            action = "report: no seniority penalty this node executed explains it; \
                      it may be a kick or a registry resync",
            "this prover's committed seniority fell between these frames, and no penalty rule is attributable");
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alloc(status: ProverStatus, epoch: u64, leave_frame: u64) -> ProverAllocationInfo {
        ProverAllocationInfo {
            status,
            confirmation_filter: vec![9; 32],
            rejection_filter: Vec::new(),
            join_frame_number: 1,
            leave_frame_number: leave_frame,
            pause_frame_number: 0,
            resume_frame_number: 0,
            kick_frame_number: 0,
            join_confirm_frame_number: 0,
            join_reject_frame_number: 0,
            leave_confirm_frame_number: 0,
            leave_reject_frame_number: 0,
            last_active_frame_number: 0,
            last_signed_frame_number: 0,
            epoch,
            ring: 0,
            vertex_address: Vec::new(),
        }
    }

    fn members(active: usize, me_active: bool) -> LifecycleMembers {
        let mut m = LifecycleMembers::default();
        for i in 0..active {
            m.active.push(vec![i as u8 + 10; 32]);
        }
        if me_active {
            m.active.push(vec![1; 32]);
        }
        m
    }

    #[test]
    fn a_departure_is_penalised_only_once_penalties_apply_and_the_shard_keeps_three() {
        let me = vec![1u8; 32];
        let frame = 100 * 720 + 5;
        let active = alloc(ProverStatus::Active, 100, 0);
        quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(None);
        assert_eq!(
            penalised_departure(&active, frame, Some(&members(3, true)), &me),
            None
        );
        quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(Some(102));
        // A proposal now departs at epoch 102.
        assert_eq!(
            penalised_departure(&active, frame, Some(&members(3, true)), &me),
            Some(PenalisedDeparture {
                departure_epoch: 102,
                remaining: 3
            })
        );
        assert_eq!(
            penalised_departure(&active, frame, Some(&members(4, true)), &me),
            None
        );
        // A pending leave confirmed now departs at epoch 101: before the epoch.
        let leaving = alloc(ProverStatus::Leaving, 99, 99 * 720 + 3);
        assert_eq!(
            penalised_departure(&leaving, frame, Some(&members(0, false)), &me),
            None
        );
        quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(Some(101));
        assert_eq!(
            penalised_departure(&leaving, frame, Some(&members(0, false)), &me),
            Some(PenalisedDeparture {
                departure_epoch: 101,
                remaining: 0
            })
        );
        // A lapsed seat counted for nothing when it left.
        let lapsed = alloc(ProverStatus::Leaving, 98, 99 * 720 + 3);
        assert_eq!(
            penalised_departure(&lapsed, frame, Some(&members(0, false)), &me),
            None
        );
        quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(None);
    }

    #[test]
    fn an_unexplained_seniority_fall_warns_once_with_its_frame_range() {
        quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(Some(0));
        let mut guard = SeniorityGuard::default();
        assert!(
            !guard.observe_seniority(100, 5_000, 0),
            "the first observation is the baseline"
        );
        assert!(
            !guard.observe_seniority(200, 5_100, 0),
            "growth is not reported"
        );
        assert!(
            !guard.observe_seniority(300, 5_090, 250),
            "a fall a recorded penalty explains"
        );
        assert!(
            guard.observe_seniority(400, 4_000, 250),
            "a fall no penalty since frame 300 explains"
        );
        assert!(
            !guard.observe_seniority(500, 4_000, 250),
            "an unchanged value is not repeated"
        );
        quil_types::consensus::set_seniority_penalty_and_succession_epoch_for_thread(None);
        assert!(
            !guard.observe_seniority(600, 1_000, 0),
            "inert before the penalty epoch"
        );
    }
}
