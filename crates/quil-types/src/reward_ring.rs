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
    if crate::consensus::committee_handoff_active(frame) {
        return committed_ring_estimate(all, owner, filter, frame);
    }
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

/// Match the activated rule's RPC view: held rings come from committed
/// allocation fields; an own pending join is ranked as its committee will
/// rank it; an unallocated prover is projected onto the tail.
fn committed_ring_estimate(
    all: &[&ProverInfo],
    owner: &[u8],
    filter: &[u8],
    frame: u64,
) -> Option<RewardRingEstimate> {
    let live: Vec<_> = all
        .iter()
        .copied()
        .filter(|p| allocation(p, filter).is_some_and(|a| a.is_live(frame)))
        .collect();
    let own_prover = live.iter().copied().find(|p| p.address == owner);
    let own = own_prover.and_then(|p| allocation(p, filter));
    if own.is_some_and(|a| a.effective_status(frame) == EffectiveStatus::Joining) {
        return join_rank_estimate(&live, own_prover?, filter, frame);
    }
    let Some(own) = own else {
        // A new join activates two epochs on; members whose confirmed leave
        // takes effect by then are gone from its committee.
        let target_frame = epoch_for_frame(frame)
            .saturating_add(2)
            .saturating_mul(epoch_length_frames());
        let staying = live
            .iter()
            .filter(|p| !departs_by(p, filter, target_frame))
            .count();
        let group = REWARD_RING_GROUP_SIZE as usize;
        return Some(RewardRingEstimate {
            ring: (staying / group) as u8,
            provers_on_ring: staying % group + 1,
            member_count: staying + 1,
            source: "new_join_projection",
            target_frame,
        });
    };
    Some(RewardRingEstimate {
        ring: own.ring,
        provers_on_ring: live
            .iter()
            .filter(|p| allocation(p, filter).is_some_and(|a| a.ring == own.ring))
            .count(),
        member_count: live.len(),
        source: "committed_allocation_ring",
        target_frame: frame,
    })
}

/// A member whose confirmed leave takes effect by `target_frame`.
fn departs_by(p: &ProverInfo, filter: &[u8], target_frame: u64) -> bool {
    allocation(p, filter).is_some_and(|a| {
        a.leave_confirm_frame_number > 0
            && a.effective_status(target_frame) == EffectiveStatus::ExpiredLeaving
    })
}

/// The epoch a live allocation's committee cohort starts: a pending join's
/// if it confirms in its only confirm epoch, a confirmed join's from its
/// confirm, zero for a member admitted without one (genesis).
fn cohort(a: &ProverAllocationInfo, frame: u64) -> u64 {
    if a.join_confirm_frame_number > 0 {
        epoch_for_frame(a.join_confirm_frame_number).saturating_add(1)
    } else if a.effective_status(frame) == EffectiveStatus::Joining {
        epoch_for_frame(a.join_frame_number).saturating_add(2)
    } else {
        0
    }
}

/// An own pending join holds no committed ring. Rank it as the committee
/// that admits it will (the seniority ring rule: cohort, then seniority,
/// most senior first, then address): members of earlier cohorts first,
/// then the joiners of its own cohort that outrank it. A later cohort's
/// joiner never moves it down; members departing before it activates do
/// not count.
fn join_rank_estimate(
    live: &[&ProverInfo],
    own: &ProverInfo,
    filter: &[u8],
    frame: u64,
) -> Option<RewardRingEstimate> {
    let key = |p: &ProverInfo| {
        allocation(p, filter).map(|a| {
            (
                cohort(a, frame),
                std::cmp::Reverse(p.seniority),
                p.address.clone(),
            )
        })
    };
    // Live seniority: the committee fixes it at the confirm, so a close
    // same-cohort pair can still swap.
    let own_key = key(own)?;
    let target_frame = own_key.0.saturating_mul(epoch_length_frames());
    let members: Vec<_> = live
        .iter()
        .copied()
        .filter(|p| {
            allocation(p, filter).is_some_and(|a| cohort(a, frame) <= own_key.0)
                && !departs_by(p, filter, target_frame)
        })
        .collect();
    let rank = members
        .iter()
        .filter(|p| p.address != own.address && key(p).is_some_and(|k| k < own_key))
        .count();
    let total = members.len().max(rank + 1);
    let group = REWARD_RING_GROUP_SIZE as usize;
    Some(RewardRingEstimate {
        ring: u8::try_from(rank / group).ok()?,
        provers_on_ring: (total - rank / group * group).min(group),
        member_count: total,
        source: "join_rank",
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
                last_signed_frame_number: 0,
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
    fn activated_rule_uses_committed_rings_and_tail_projection() {
        let mut ps: Vec<_> = (1..=9).map(|id| prover(id, 1)).collect();
        for p in &mut ps {
            p.allocations[0].ring = 0;
        }
        ps[0].allocations[0].ring = 1;
        let all: Vec<_> = ps.iter().collect();
        let e = committed_ring_estimate(&all, &[1; 32], &[1], 10).unwrap();
        assert_eq!((e.ring, e.provers_on_ring), (1, 1));
        assert_eq!(e.source, "committed_allocation_ring");
        let projected = committed_ring_estimate(&all, &[10; 32], &[1], 10).unwrap();
        assert_eq!((projected.ring, projected.provers_on_ring), (1, 2));
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

    /// A shard of 30 members (rings 0-3) with three joins pending their
    /// confirm epoch: the owner (id 33) holds `seniority`, the other two
    /// joiners 500 and 400. A later epoch's joiner (id 34, most senior) and
    /// a member departing before activation (id 35) are present too.
    fn pending_join_shard(seniority: u64) -> (Vec<ProverInfo>, u64) {
        let e = epoch_length_frames();
        let mut ps: Vec<_> = (1..=30).map(|id| prover(id, 0)).collect();
        for (i, p) in ps.iter_mut().enumerate() {
            p.allocations[0].ring = (i / 8) as u8;
            p.allocations[0].epoch = u64::MAX;
        }
        let mut departing = prover(35, 0);
        departing.allocations[0].status = ProverStatus::Leaving;
        departing.allocations[0].leave_frame_number = 9 * e;
        departing.allocations[0].leave_confirm_frame_number = 10 * e + 1;
        ps.push(departing);
        for (id, senior, join) in [
            (31, 500, 9 * e + 3),
            (32, 400, 9 * e + 7),
            (33, seniority, 9 * e + 9),
            (34, u64::MAX, 10 * e + 2),
        ] {
            let mut p = prover(id, join);
            p.seniority = senior;
            p.allocations[0].status = ProverStatus::Joining;
            ps.push(p);
        }
        (ps, 10 * e + 5)
    }

    fn own_join_rank(seniority: u64) -> RewardRingEstimate {
        let (ps, frame) = pending_join_shard(seniority);
        let all: Vec<_> = ps.iter().collect();
        committed_ring_estimate(&all, &[33; 32], &[1], frame).unwrap()
    }

    /// Ranked as its committee will rank it, the most senior of three
    /// pending joiners takes rank 30 (ring 3), not the shard-wide count's
    /// ring 4.
    #[test]
    fn own_pending_join_ranks_ahead_of_less_senior_joiners() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let e = own_join_rank(900);
        assert_eq!(e.source, "join_rank", "pending_join_unranked");
        assert_eq!(
            (e.ring, e.provers_on_ring, e.member_count),
            (3, 8, 33),
            "pending_join_misranked"
        );
        assert_eq!(e.target_frame, 11 * epoch_length_frames());
    }

    /// Mutation control: the least senior of the three joiners ranks last
    /// (rank 32) and lands on ring 4 alone.
    #[test]
    fn own_pending_join_ranks_behind_more_senior_joiners() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let e = own_join_rank(100);
        assert_eq!(e.source, "join_rank", "pending_join_unranked");
        assert_eq!(
            (e.ring, e.provers_on_ring, e.member_count),
            (4, 1, 33),
            "pending_join_misranked"
        );
    }

    /// The incident's tie: ours and one other joiner share the least
    /// seniority (400), behind one more senior joiner (500), so the address
    /// alone decides the last seat of ring 3. The tied joiner's address is
    /// `[other; 32]`; ours is `[33; 32]`.
    fn own_join_rank_tied_with(other: u8) -> RewardRingEstimate {
        let (mut ps, frame) = pending_join_shard(400);
        let tied = ps.iter_mut().find(|p| p.address == [32; 32]).unwrap();
        assert_eq!(tied.seniority, 400, "fixture: the tie must hold");
        tied.address = vec![other; 32];
        let all: Vec<_> = ps.iter().collect();
        committed_ring_estimate(&all, &[33; 32], &[1], frame).unwrap()
    }

    /// Tied on seniority with a higher-address joiner, ours takes rank 31,
    /// the last seat of ring 3, and confirms there.
    #[test]
    fn own_pending_join_wins_a_seniority_tie_on_the_lower_address() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let e = own_join_rank_tied_with(0x40);
        assert_eq!(e.source, "join_rank", "pending_join_unranked");
        assert_eq!(
            (e.ring, e.provers_on_ring, e.member_count),
            (3, 8, 33),
            "pending_join_misranked"
        );
    }

    /// Mutation control: tied with a lower-address joiner, ours takes rank
    /// 32 and lands on ring 4 alone.
    #[test]
    fn own_pending_join_loses_a_seniority_tie_on_the_higher_address() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let e = own_join_rank_tied_with(0x20);
        assert_eq!(e.source, "join_rank", "pending_join_unranked");
        assert_eq!(
            (e.ring, e.provers_on_ring, e.member_count),
            (4, 1, 33),
            "pending_join_misranked"
        );
    }

    /// Confirm a pending join at `at`: the byte flips to Active and the
    /// seat reads Joining until the epoch after the confirm.
    fn confirm_join(ps: &mut [ProverInfo], id: u8, at: u64, frame: u64) {
        let p = ps.iter_mut().find(|p| p.address == [id; 32]).unwrap();
        p.allocations[0].status = ProverStatus::Active;
        p.allocations[0].join_confirm_frame_number = at;
        let a = &p.allocations[0];
        assert!(
            a.is_live(frame) && a.effective_status(frame) == EffectiveStatus::Joining,
            "fixture: a confirmed join must read live Joining until it activates"
        );
    }

    /// A joiner of our cohort whose join confirmed in its confirm epoch
    /// (epoch 10) activates with ours at epoch 11, so its seniority, not its
    /// confirm, places it: holding less seniority (400) than ours (450), it
    /// ranks behind ours, which takes rank 31, the last seat of ring 3.
    #[test]
    fn a_confirmed_same_cohort_joiner_with_less_seniority_ranks_behind_ours() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let e = epoch_length_frames();
        let (mut ps, frame) = pending_join_shard(450);
        confirm_join(&mut ps, 32, 10 * e + 1, frame);
        let all: Vec<_> = ps.iter().collect();
        let r = committed_ring_estimate(&all, &[33; 32], &[1], frame).unwrap();
        assert_eq!(r.source, "join_rank", "pending_join_unranked");
        assert_eq!(
            (r.ring, r.provers_on_ring, r.member_count),
            (3, 8, 33),
            "pending_join_misranked"
        );
        assert_eq!(r.target_frame, 11 * e, "pending_join_misranked");
    }

    /// Our own join, once its confirm lands (epoch 10), still ranks in the
    /// cohort it activates with (epoch 11): behind the more senior pending
    /// joiner (500), ahead of the less senior one (400) and of the later
    /// epoch's joiner, so rank 31, the last seat of ring 3.
    #[test]
    fn own_confirmed_join_ranks_in_its_activation_cohort() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let e = epoch_length_frames();
        let (mut ps, frame) = pending_join_shard(450);
        confirm_join(&mut ps, 33, 10 * e + 1, frame);
        let all: Vec<_> = ps.iter().collect();
        let r = committed_ring_estimate(&all, &[33; 32], &[1], frame).unwrap();
        assert_eq!(r.source, "join_rank", "pending_join_unranked");
        assert_eq!(
            (r.ring, r.provers_on_ring, r.member_count),
            (3, 8, 33),
            "pending_join_misranked"
        );
        assert_eq!(r.target_frame, 11 * e, "pending_join_misranked");
    }

    /// Past the handoff, a new join's tail projection drops a member whose
    /// confirmed leave takes effect before the join can activate, as the
    /// pre-handoff projection does: of 8 live members one departs, so the
    /// joiner takes the last seat of ring 0, not ring 1.
    #[test]
    fn activated_new_join_projection_excludes_confirmed_departure() {
        let _epoch = crate::consensus::epoch_tests::epoch_length_guard();
        let e = epoch_length_frames();
        let mut ps: Vec<_> = (1..=8).map(|id| prover(id, 0)).collect();
        for p in &mut ps {
            p.allocations[0].ring = 0;
            p.allocations[0].epoch = u64::MAX;
        }
        ps[0].allocations[0].status = ProverStatus::Leaving;
        ps[0].allocations[0].leave_frame_number = 9 * e;
        ps[0].allocations[0].leave_confirm_frame_number = 10 * e + 1;
        let all: Vec<_> = ps.iter().collect();
        assert!(
            all.iter().all(|p| p.allocations[0].is_live(10 * e + 5)),
            "fixture: all eight members must be live"
        );
        let p = committed_ring_estimate(&all, &[10; 32], &[1], 10 * e + 5).unwrap();
        assert_eq!(p.source, "new_join_projection");
        assert_eq!(
            (p.ring, p.provers_on_ring, p.member_count),
            (0, 8, 8),
            "departure_counted"
        );
        assert_eq!(p.target_frame, 12 * e);
    }
}
