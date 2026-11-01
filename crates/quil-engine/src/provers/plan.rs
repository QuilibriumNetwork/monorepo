//! Compile policy candidates into one lifecycle intent per shard before any
//! asynchronous submission. This is a local plan, not protocol authorization
//! or a persisted replacement reservation. Registry observation remains the
//! authority after publication and restart.

use super::lifecycle::LifecycleAction;
use quil_types::error::{QuilError, Result};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Intent {
    Join,
    ConfirmJoin,
    RejectJoin,
    Leave,
    ConfirmLeave,
    Renew,
    RejectLeave,
}

impl Intent {
    fn bit(self) -> u8 {
        1 << self as u8
    }
}

#[derive(Default)]
struct ShardPlan {
    candidates: u8,
    worker: Option<u32>,
}

impl ShardPlan {
    fn resolve(&self) -> Result<Intent> {
        let has = |intent: Intent| self.candidates & intent.bit() != 0;
        // Capacity rejection takes precedence over a score-based join confirm.
        // Renewal cannot overlap a departure or a leave rejection: wait for
        // the rejected leave to be observed before renewing the Active row.
        let mut candidates = self.candidates;
        if has(Intent::RejectJoin) {
            candidates &= !Intent::ConfirmJoin.bit();
        }
        if has(Intent::Leave) || has(Intent::ConfirmLeave) || has(Intent::RejectLeave) {
            candidates &= !Intent::Renew.bit();
        }
        if candidates.count_ones() != 1 {
            return Err(QuilError::Internal(
                "incompatible per-shard lifecycle intents".into(),
            ));
        }
        [
            Intent::Join,
            Intent::ConfirmJoin,
            Intent::RejectJoin,
            Intent::Leave,
            Intent::ConfirmLeave,
            Intent::Renew,
            Intent::RejectLeave,
        ]
        .into_iter()
        .find(|intent| candidates == intent.bit())
        .ok_or_else(|| QuilError::Internal("missing per-shard lifecycle intent".into()))
    }
}

/// A frame-scoped plan validated in full before dispatch. Keep the original
/// batch and ranking order; arbitration must not reorder reward priorities.
pub(crate) struct LifecyclePlan {
    actions: Vec<LifecycleAction>,
}

impl LifecyclePlan {
    pub(crate) fn compile(frame: u64, mut actions: Vec<LifecycleAction>) -> Result<Self> {
        let mut shards: BTreeMap<Vec<u8>, ShardPlan> = BTreeMap::new();
        let mut workers = BTreeMap::new();
        for action in &actions {
            let Some((intent, filters, action_frame)) = parts(action) else {
                if let LifecycleAction::ProposeSeniorityMerge { frame_number } = action {
                    if *frame_number != frame {
                        return Err(wrong_frame());
                    }
                }
                continue;
            };
            if action_frame != frame {
                return Err(wrong_frame());
            }
            let ids = match action {
                LifecycleAction::ProposeJoin { worker_ids, .. } => {
                    if worker_ids.len() != filters.len() {
                        return Err(QuilError::Internal(
                            "join plan has unmatched filters and workers".into(),
                        ));
                    }
                    Some(worker_ids)
                }
                _ => None,
            };
            for (index, filter) in filters.iter().enumerate() {
                let shard = shards.entry(filter.clone()).or_default();
                shard.candidates |= intent.bit();
                if let Some(ids) = ids {
                    let worker = ids[index];
                    if shard.worker.is_some_and(|old| old != worker)
                        || workers.get(&worker).is_some_and(|old| old != filter)
                    {
                        return Err(QuilError::Internal(
                            "join plan assigns conflicting worker reservations".into(),
                        ));
                    }
                    shard.worker = Some(worker);
                    workers.insert(worker, filter.clone());
                }
            }
        }
        let resolved: BTreeMap<_, _> = shards
            .iter()
            .map(|(filter, plan)| Ok((filter.clone(), plan.resolve()?)))
            .collect::<Result<_>>()?;
        let mut emitted = HashSet::new();
        let mut merge_emitted = false;
        actions.retain_mut(|action| {
            let Some((intent, _, _)) = parts(action) else {
                return match action {
                    LifecycleAction::ProposeSeniorityMerge { .. } if !merge_emitted => {
                        merge_emitted = true;
                        true
                    }
                    _ => false,
                };
            };
            let keep = |filter: &Vec<u8>, emitted: &mut HashSet<Vec<u8>>| {
                resolved.get(filter) == Some(&intent) && emitted.insert(filter.clone())
            };
            match action {
                LifecycleAction::ProposeJoin {
                    filters,
                    worker_ids,
                    ..
                } => {
                    let mut index = 0;
                    let mut retained_workers = Vec::with_capacity(worker_ids.len());
                    filters.retain(|filter| {
                        let accepted = keep(filter, &mut emitted);
                        if accepted {
                            retained_workers.push(worker_ids[index]);
                        }
                        index += 1;
                        accepted
                    });
                    *worker_ids = retained_workers;
                    !filters.is_empty()
                }
                LifecycleAction::ConfirmJoins { filters, .. }
                | LifecycleAction::RejectJoins { filters, .. }
                | LifecycleAction::ProposeLeave { filters, .. }
                | LifecycleAction::ConfirmLeaves { filters, .. }
                | LifecycleAction::ReconfirmEpoch { filters, .. }
                | LifecycleAction::RejectLeaves { filters, .. } => {
                    filters.retain(|filter| keep(filter, &mut emitted));
                    !filters.is_empty()
                }
                _ => false,
            }
        });
        Ok(Self { actions })
    }

    pub(crate) fn into_actions(self) -> Vec<LifecycleAction> {
        self.actions
    }
}

fn wrong_frame() -> QuilError {
    QuilError::Internal("lifecycle plan mixes evaluation frames".into())
}

fn parts(action: &LifecycleAction) -> Option<(Intent, &Vec<Vec<u8>>, u64)> {
    let (intent, filters, frame) = match action {
        LifecycleAction::ProposeJoin {
            filters,
            frame_number,
            ..
        } => (Intent::Join, filters, *frame_number),
        LifecycleAction::ConfirmJoins {
            filters,
            frame_number,
        } => (Intent::ConfirmJoin, filters, *frame_number),
        LifecycleAction::RejectJoins {
            filters,
            frame_number,
        } => (Intent::RejectJoin, filters, *frame_number),
        LifecycleAction::ProposeLeave {
            filters,
            frame_number,
        } => (Intent::Leave, filters, *frame_number),
        LifecycleAction::ConfirmLeaves {
            filters,
            frame_number,
        } => (Intent::ConfirmLeave, filters, *frame_number),
        LifecycleAction::ReconfirmEpoch {
            filters,
            frame_number,
        } => (Intent::Renew, filters, *frame_number),
        LifecycleAction::RejectLeaves {
            filters,
            frame_number,
        } => (Intent::RejectLeave, filters, *frame_number),
        _ => return None,
    };
    Some((intent, filters, frame))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn candidate(kind: u8, filters: Vec<Vec<u8>>) -> LifecycleAction {
        match kind {
            0 => LifecycleAction::ProposeJoin {
                worker_ids: (0..filters.len() as u32).collect(),
                filters,
                frame_number: 720,
            },
            1 => LifecycleAction::ConfirmJoins {
                filters,
                frame_number: 720,
            },
            2 => LifecycleAction::RejectJoins {
                filters,
                frame_number: 720,
            },
            3 => LifecycleAction::ProposeLeave {
                filters,
                frame_number: 720,
            },
            4 => LifecycleAction::ConfirmLeaves {
                filters,
                frame_number: 720,
            },
            5 => LifecycleAction::ReconfirmEpoch {
                filters,
                frame_number: 720,
            },
            6 => LifecycleAction::RejectLeaves {
                filters,
                frame_number: 720,
            },
            _ => unreachable!(),
        }
    }

    #[test]
    fn all_action_pairs_have_order_independent_compatibility() {
        // Independent specification: only these mixed pairs are compatible.
        // Every other mixed pair must prevent the entire batch from dispatch.
        let compatible = [(1, 2, 2), (3, 5, 3), (4, 5, 4), (5, 6, 6)];
        for first in 0..7 {
            for second in 0..7 {
                let expected = if first == second {
                    Some(first)
                } else {
                    compatible
                        .iter()
                        .find(|(a, b, _)| {
                            (*a == first && *b == second) || (*a == second && *b == first)
                        })
                        .map(|(_, _, winner)| *winner)
                };
                let plan = LifecyclePlan::compile(
                    720,
                    vec![
                        candidate(first, vec![vec![1]]),
                        candidate(second, vec![vec![1]]),
                    ],
                );
                match expected {
                    Some(winner) => {
                        let actions = plan.unwrap().into_actions();
                        assert_eq!(actions.len(), 1, "pair={first}/{second}");
                        assert_eq!(parts(&actions[0]).unwrap().0 as u8, winner);
                    }
                    None => assert!(plan.is_err(), "pair={first}/{second}"),
                }
            }
        }
    }

    #[test]
    fn mixed_shards_keep_ranked_batches_and_distinct_intents() {
        let actions = LifecyclePlan::compile(
            720,
            vec![
                candidate(5, vec![vec![9], vec![8], vec![7]]),
                candidate(3, vec![vec![8]]),
                candidate(1, vec![vec![4], vec![3]]),
                candidate(2, vec![vec![3]]),
            ],
        )
        .unwrap()
        .into_actions();
        assert_eq!(parts(&actions[0]).unwrap().1, &vec![vec![9], vec![7]]);
        assert!(
            matches!(&actions[1], LifecycleAction::ProposeLeave { filters, .. } if filters == &vec![vec![8]])
        );
        assert!(
            matches!(&actions[2], LifecycleAction::ConfirmJoins { filters, .. } if filters == &vec![vec![4]])
        );
        assert!(
            matches!(&actions[3], LifecycleAction::RejectJoins { filters, .. } if filters == &vec![vec![3]])
        );
    }

    #[test]
    fn duplicate_joins_keep_worker_filter_correspondence() {
        let actions = LifecyclePlan::compile(
            720,
            vec![
                LifecycleAction::ProposeJoin {
                    filters: vec![vec![8]],
                    worker_ids: vec![4],
                    frame_number: 720,
                },
                LifecycleAction::ProposeJoin {
                    filters: vec![vec![8], vec![7]],
                    worker_ids: vec![4, 3],
                    frame_number: 720,
                },
            ],
        )
        .unwrap()
        .into_actions();
        assert!(
            matches!(&actions[1], LifecycleAction::ProposeJoin { filters, worker_ids, .. } if filters == &vec![vec![7]] && worker_ids == &vec![3])
        );
    }

    #[test]
    fn malformed_or_conflicting_worker_claims_fail_before_dispatch() {
        for ids in [vec![4], vec![4, 4]] {
            assert!(LifecyclePlan::compile(
                720,
                vec![LifecycleAction::ProposeJoin {
                    filters: vec![vec![8], vec![7]],
                    worker_ids: ids,
                    frame_number: 720,
                }]
            )
            .is_err());
        }
        assert!(LifecyclePlan::compile(
            720,
            vec![
                LifecycleAction::ProposeJoin {
                    filters: vec![vec![8]],
                    worker_ids: vec![4],
                    frame_number: 720
                },
                LifecycleAction::ProposeJoin {
                    filters: vec![vec![8]],
                    worker_ids: vec![3],
                    frame_number: 720
                },
            ]
        )
        .is_err());
    }

    #[test]
    fn plans_do_not_mix_frames() {
        assert!(LifecyclePlan::compile(721, vec![candidate(5, vec![vec![1]])]).is_err());
        assert!(LifecyclePlan::compile(
            721,
            vec![LifecycleAction::ProposeSeniorityMerge { frame_number: 720 }]
        )
        .is_err());
    }
}
