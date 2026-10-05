//! Reward-position estimates for legacy registry-derived committees.
//! A decoded allocation ring can be absent or stale. Current estimates use
//! the same immutable ordering as issuance; projections are not entitlements.

use crate::consensus::{
    epoch_for_frame, epoch_length_frames, EffectiveStatus, ProverAllocationInfo, ProverInfo,
};

pub const REWARD_RING_GROUP_SIZE: u64 = 8;

fn allocation<'a>(prover: &'a ProverInfo, filter: &[u8]) -> Option<&'a ProverAllocationInfo> {
    prover
        .allocations
        .iter()
        .find(|a| a.confirmation_filter == filter)
}

#[derive(Debug, Clone, Copy)]
pub struct RewardRingEstimate {
    pub ring: u8,
    pub provers_on_ring: usize,
    pub member_count: usize,
    pub source: &'static str,
    pub target_frame: u64,
}

/// Issuance's ordering: original join frame, then address. Seniority and the
/// last stored ring do not affect rank. Callers supply eligible members.
pub fn reward_member_order(provers: &[&ProverInfo], filter: &[u8]) -> Vec<usize> {
    let join = |p: &ProverInfo| {
        p.allocations
            .iter()
            .find(|a| a.confirmation_filter == filter)
            .map(|a| a.join_frame_number)
            .unwrap_or(0)
    };
    let mut order: Vec<_> = (0..provers.len()).collect();
    order.sort_by(|&i, &j| {
        join(provers[i])
            .cmp(&join(provers[j]))
            .then_with(|| provers[i].address.cmp(&provers[j].address))
    });
    order
}

/// `committee` must be the registry's actual committee at `frame`, including
/// its legacy empty-committee floor. Current Active/Leaving positions exactly
/// follow issuance. A join projection assumes eligible pending joins succeed
/// and current members renew, excluding already confirmed departures by the
/// target activation frame. Paused/recovering estimates insert only this
/// allocation into the current committee. None means a live owner is missing
/// from an otherwise nonempty committee, so a current rank is not established.
pub fn estimate_reward_ring(
    committee: &[&ProverInfo],
    all: &[&ProverInfo],
    owner: &[u8],
    filter: &[u8],
    frame: u64,
) -> Option<RewardRingEstimate> {
    let committee: Vec<_> = committee
        .iter()
        .copied()
        .filter(|p| allocation(p, filter).is_some())
        .collect();
    let own = all.iter().copied().find(|p| p.address == owner);
    let status = own
        .and_then(|p| allocation(p, filter))
        .map(|a| a.effective_status(frame));
    let in_committee = committee.iter().any(|p| p.address == owner);
    let (source, target_frame, project_joins) = match status {
        Some(EffectiveStatus::Active | EffectiveStatus::Leaving) => {
            if !in_committee {
                return None;
            }
            ("current_committee", frame, false)
        }
        Some(EffectiveStatus::Joining | EffectiveStatus::ExpiredEpoch) if in_committee => {
            ("legacy_committee_floor", frame, false)
        }
        Some(EffectiveStatus::Paused) => ("resume_projection", frame, false),
        Some(EffectiveStatus::ExpiredEpoch) => ("renewal_projection", frame, false),
        Some(EffectiveStatus::Joining) => {
            let a = allocation(own?, filter)?;
            let activation = if a.join_confirm_frame_number > 0 {
                epoch_for_frame(a.join_confirm_frame_number).saturating_add(1)
            } else {
                epoch_for_frame(a.join_frame_number).saturating_add(2)
            };
            (
                "join_projection",
                activation.saturating_mul(epoch_length_frames()),
                true,
            )
        }
        _ => (
            "new_join_projection",
            epoch_for_frame(frame)
                .saturating_add(2)
                .saturating_mul(epoch_length_frames()),
            true,
        ),
    };
    let mut members: Vec<_> = committee
        .iter()
        .copied()
        .filter(|p| {
            !project_joins
                || !allocation(p, filter).is_some_and(|a| {
                    a.leave_confirm_frame_number > 0
                        && a.effective_status(target_frame) == EffectiveStatus::ExpiredLeaving
                })
        })
        .collect();
    if project_joins {
        for p in all.iter().copied().filter(|p| {
            allocation(p, filter).is_some_and(|a| {
                a.effective_status(frame) == EffectiveStatus::Joining
                    && (if a.join_confirm_frame_number > 0 {
                        epoch_for_frame(a.join_confirm_frame_number).saturating_add(1)
                    } else {
                        epoch_for_frame(a.join_frame_number).saturating_add(2)
                    })
                    .saturating_mul(epoch_length_frames())
                        <= target_frame
            })
        }) {
            if !members.iter().any(|m| m.address == p.address) {
                members.push(p);
            }
        }
    }
    if matches!(
        status,
        Some(EffectiveStatus::Paused | EffectiveStatus::ExpiredEpoch)
    ) && !in_committee
    {
        members.push(own?);
    }
    let order = reward_member_order(&members, filter);
    let rank = order
        .iter()
        .position(|&i| members[i].address == owner)
        .unwrap_or(members.len());
    let total = members.len() + usize::from(rank == members.len());
    let group = REWARD_RING_GROUP_SIZE as usize;
    Some(RewardRingEstimate {
        ring: (rank / group) as u8,
        provers_on_ring: (total - rank / group * group).min(group),
        member_count: total,
        source,
        target_frame,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ProverStatus;

    fn prover(id: u8, join: u64) -> ProverInfo {
        ProverInfo {
            public_key: vec![id; 585],
            address: vec![id; 32],
            status: ProverStatus::Active,
            kick_frame_number: 0,
            available_storage: 0,
            seniority: 1000 - u64::from(id),
            delegate_address: vec![],
            allocations: vec![ProverAllocationInfo {
                status: ProverStatus::Active,
                confirmation_filter: vec![1],
                rejection_filter: vec![],
                join_frame_number: join,
                leave_frame_number: 0,
                pause_frame_number: 0,
                resume_frame_number: 0,
                kick_frame_number: 0,
                join_confirm_frame_number: 0,
                join_reject_frame_number: 0,
                leave_confirm_frame_number: 0,
                leave_reject_frame_number: 0,
                last_active_frame_number: 0,
                epoch: 10,
                ring: 99,
                vertex_address: vec![],
            }],
        }
    }
    fn estimate(ps: &[ProverInfo], owner: u8, frame: u64) -> Option<RewardRingEstimate> {
        let all: Vec<_> = ps.iter().collect();
        let committee: Vec<_> = ps
            .iter()
            .filter(|p| {
                matches!(
                    p.allocations[0].effective_status(frame),
                    EffectiveStatus::Active | EffectiveStatus::Leaving
                )
            })
            .collect();
        estimate_reward_ring(&committee, &all, &[owner; 32], &[1], frame)
    }
    #[test]
    fn current_rank_uses_issuance_order_not_seniority_or_stored_default() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let mut ps: Vec<_> = (1..=9).map(|id| prover(id, 1)).collect();
        ps[8].seniority = u64::MAX;
        ps[8].allocations[0].ring = 0;
        let e = estimate(&ps, 9, 10).unwrap();
        assert_eq!((e.ring, e.provers_on_ring, e.member_count), (1, 1, 9));
        assert_eq!(e.source, "current_committee");
        ps[8].allocations[0].join_frame_number = 0;
        assert_eq!(estimate(&ps, 9, 10).unwrap().ring, 0);
    }
    #[test]
    fn joining_member_does_not_shift_an_established_members_rank() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let mut ps: Vec<_> = (1..=9).map(|id| prover(id, 1)).collect();
        ps[0].allocations[0].status = ProverStatus::Joining;
        assert_eq!(estimate(&ps, 9, 10).unwrap().ring, 0);
        let e = estimate(&ps, 1, 10).unwrap();
        assert_eq!(
            (e.source, e.member_count, e.target_frame),
            ("join_projection", 9, 2 * epoch_length_frames())
        );
    }
    #[test]
    fn notice_member_counts_until_effective_departure() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let mut ps: Vec<_> = (1..=9).map(|id| prover(id, 1)).collect();
        ps[0].allocations[0].status = ProverStatus::Leaving;
        ps[0].allocations[0].leave_confirm_frame_number = epoch_length_frames();
        assert_eq!(estimate(&ps, 9, epoch_length_frames()).unwrap().ring, 1);
        assert_eq!(estimate(&ps, 9, 2 * epoch_length_frames()).unwrap().ring, 0);
    }
    #[test]
    fn projected_join_excludes_confirmed_departure() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let mut ps: Vec<_> = (1..=9).map(|id| prover(id, 1)).collect();
        ps[0].allocations[0].status = ProverStatus::Leaving;
        ps[0].allocations[0].leave_confirm_frame_number = epoch_length_frames();
        ps[8].allocations[0].status = ProverStatus::Joining;
        assert_eq!(
            estimate(&ps, 9, epoch_length_frames())
                .unwrap()
                .member_count,
            8
        );
        assert_eq!(estimate(&ps, 9, epoch_length_frames()).unwrap().ring, 0);
    }
    #[test]
    fn paused_and_expired_members_have_explicit_recovery_projections() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let mut ps = vec![prover(1, 1), prover(2, 2)];
        ps[1].allocations[0].status = ProverStatus::Paused;
        assert_eq!(estimate(&ps, 2, 10).unwrap().source, "resume_projection");
        ps[1].allocations[0].status = ProverStatus::Active;
        ps[1].allocations[0].epoch = 0;
        assert_eq!(
            estimate(&ps, 2, epoch_length_frames()).unwrap().source,
            "renewal_projection"
        );
    }
    #[test]
    fn missing_live_member_is_unknown_not_ring_zero() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let ps = vec![prover(1, 1), prover(2, 2)];
        assert!(estimate_reward_ring(&[&ps[0]], &[&ps[0], &ps[1]], &[2; 32], &[1], 10).is_none());
    }
    #[test]
    fn legacy_floor_uses_the_actual_supplied_committee() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let mut p = prover(1, 1);
        p.allocations[0].epoch = 0;
        let e =
            estimate_reward_ring(&[&p], &[&p], &p.address, &[1], epoch_length_frames()).unwrap();
        assert_eq!(e.source, "legacy_committee_floor");
    }
    #[test]
    fn available_join_uses_tail_and_ignores_other_filters() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let ps: Vec<_> = (1..=8).map(|id| prover(id, 1)).collect();
        let mut unrelated = prover(0, 0);
        unrelated.allocations[0].confirmation_filter = vec![2];
        let mut all: Vec<_> = ps.iter().collect();
        all.push(&unrelated);
        let e = estimate_reward_ring(&all, &all, &[9; 32], &[1], 10).unwrap();
        assert_eq!((e.ring, e.provers_on_ring, e.member_count), (1, 1, 9));
    }
}
