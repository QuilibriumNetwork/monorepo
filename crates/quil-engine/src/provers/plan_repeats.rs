//! One log story for a lifecycle plan that repeats. The lifecycle plans each
//! frame what it still owes, so an operation the registry does not yet show (a
//! leave confirm every node refuses, say) is planned again every frame while its
//! retry fence holds off nearly all sends. Log the work when it is new, the
//! repeat's start, bounded repeats with their duration and its end
//! ([`crate::outage`]), not several lines per frame.
use std::collections::HashSet;
use std::time::Instant;

use super::lifecycle::LifecycleAction;
use crate::outage::{Outage, OutageEvent};

/// What an action asks for, whatever frame it was planned at.
type Work = (&'static str, Vec<Vec<u8>>);

/// `None` for a `Noop`, which asks for nothing: it cannot repeat or be new.
fn work_of(action: &LifecycleAction) -> Option<Work> {
    Some(match action {
        LifecycleAction::Noop => return None,
        LifecycleAction::ProposeJoin { filters, .. } => ("join", filters.clone()),
        LifecycleAction::ConfirmJoins { filters, .. } => ("confirm join", filters.clone()),
        LifecycleAction::RejectJoins { filters, .. } => ("reject join", filters.clone()),
        LifecycleAction::ProposeLeave { filters, .. } => ("leave", filters.clone()),
        LifecycleAction::ConfirmLeaves { filters, .. } => ("confirm leave", filters.clone()),
        LifecycleAction::ReconfirmEpoch { filters, .. } => ("renew", filters.clone()),
        LifecycleAction::RejectLeaves { filters, .. } => ("reject leave", filters.clone()),
        LifecycleAction::ProposeSeniorityMerge { .. } => ("seniority merge", Vec::new()),
    })
}

/// The counts of `lifecycle leave decision causes`.
pub(crate) type LeaveCauses = [usize; 9];

/// What one plan adds to the log.
pub(crate) struct Observed {
    /// The plan holds work the last one did not: log the plan.
    pub(crate) new_work: bool,
    /// The repeat's transition to log.
    pub(crate) event: Option<OutageEvent>,
    /// The frame the repeat began at.
    pub(crate) since_frame: u64,
}

#[derive(Default)]
pub(crate) struct PlanRepeats {
    last: HashSet<Work>,
    fresh: HashSet<Work>,
    repeat: Outage,
    since_frame: u64,
    causes: Option<LeaveCauses>,
}

impl PlanRepeats {
    pub(crate) fn observe(
        &mut self,
        actions: &[LifecycleAction],
        frame: u64,
        now: Instant,
    ) -> Observed {
        let current: HashSet<Work> = actions.iter().filter_map(work_of).collect();
        self.fresh = current.difference(&self.last).cloned().collect();
        let repeats = current.len() > self.fresh.len();
        let event = self.repeat.observe(now, !repeats);
        if matches!(event, Some(OutageEvent::Began)) {
            self.since_frame = frame;
        }
        if !actions.iter().any(|a| {
            matches!(
                a,
                LifecycleAction::ConfirmLeaves { .. } | LifecycleAction::RejectLeaves { .. }
            )
        }) {
            self.causes = None;
        }
        self.last = current;
        Observed {
            new_work: !self.fresh.is_empty(),
            event,
            since_frame: self.since_frame,
        }
    }

    /// Whether `action`, of the latest plan, was not in the one before it.
    pub(crate) fn is_new(&self, action: &LifecycleAction) -> bool {
        work_of(action).is_some_and(|work| self.fresh.contains(&work))
    }

    /// Whether the latest plan repeats work on any of `filters`.
    pub(crate) fn repeats_filters(&self, filters: &[Vec<u8>]) -> bool {
        self.last.iter().any(|work| {
            !self.fresh.contains(work) && work.1.iter().any(|filter| filters.contains(filter))
        })
    }

    /// The latest plan's repeated work, for its line.
    pub(crate) fn repeated(&self) -> Vec<String> {
        let mut work: Vec<String> = self
            .last
            .difference(&self.fresh)
            .map(|(kind, filters)| {
                let filters: Vec<String> = filters.iter().map(hex::encode).collect();
                format!("{kind} {}", filters.join(","))
            })
            .collect();
        work.sort();
        work
    }

    /// Whether the leave decision's counts differ from those last logged.
    pub(crate) fn causes_changed(&mut self, causes: LeaveCauses) -> bool {
        self.causes.replace(causes) != Some(causes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn confirm(filter: u8, frame_number: u64) -> LifecycleAction {
        LifecycleAction::ConfirmLeaves {
            filters: vec![vec![filter; 32]],
            frame_number,
        }
    }

    /// A leave confirm refused through a mainnet confirm epoch, 720 frames of
    /// 10 s: the plan once, the repeat's start, one repeat per 10 minutes with
    /// its duration and count, and its end.
    #[test]
    fn a_plan_refused_for_an_epoch_logs_a_bounded_story() {
        let mut repeats = PlanRepeats::default();
        let start = Instant::now();
        let at = |frame: u64| start + Duration::from_secs(frame * 10);
        let (mut plans, mut began, mut continues) = (0, 0, Vec::new());
        for frame in 0..720 {
            let seen = repeats.observe(&[confirm(1, 720 + frame)], 720 + frame, at(frame));
            plans += usize::from(seen.new_work);
            match seen.event {
                Some(OutageEvent::Began) => {
                    began += 1;
                    assert_eq!(seen.since_frame, 721);
                }
                Some(OutageEvent::Continues { secs, failures }) => continues.push((secs, failures)),
                Some(OutageEvent::Ended { .. }) => panic!("it has not ended"),
                None => {}
            }
        }
        assert_eq!((plans, began), (1, 1));
        assert_eq!(continues.len(), 11);
        assert_eq!(continues[0], (600, 61));
        let end = repeats.observe(&[], 1440, at(720));
        assert!(!end.new_work);
        assert_eq!(
            end.event,
            Some(OutageEvent::Ended {
                secs: 7190,
                failures: 719
            })
        );
    }

    /// New work speaks at once beside a repeat, and only it counts as new.
    #[test]
    fn new_work_is_told_apart_from_a_repeat() {
        let mut repeats = PlanRepeats::default();
        let now = Instant::now();
        let (a, b) = (vec![1; 32], vec![2; 32]);
        assert!(repeats.observe(&[confirm(1, 5)], 5, now).new_work);
        assert!(repeats.is_new(&confirm(1, 5)));
        assert!(!repeats.repeats_filters(std::slice::from_ref(&a)));

        let seen = repeats.observe(&[confirm(1, 6), confirm(2, 6)], 6, now);
        assert!(seen.new_work);
        assert_eq!(seen.event, Some(OutageEvent::Began));
        assert!(!repeats.is_new(&confirm(1, 6)), "the frame does not matter");
        assert!(repeats.is_new(&confirm(2, 6)));
        assert!(repeats.repeats_filters(std::slice::from_ref(&a)));
        assert!(!repeats.repeats_filters(std::slice::from_ref(&b)));
        assert_eq!(
            repeats.repeated(),
            vec![format!("confirm leave {}", hex::encode(&a))]
        );
    }

    /// A `Noop` asks for nothing: never new work, never a repeat.
    #[test]
    fn a_noop_is_no_work() {
        let mut repeats = PlanRepeats::default();
        let now = Instant::now();
        for frame in [5, 6] {
            let seen = repeats.observe(&[LifecycleAction::Noop], frame, now);
            assert!(!seen.new_work);
            assert_eq!(seen.event, None);
            assert!(!repeats.is_new(&LifecycleAction::Noop));
        }
    }

    /// The decision's counts speak on a change, and again for a later leave.
    #[test]
    fn leave_causes_log_when_they_change() {
        let mut repeats = PlanRepeats::default();
        let now = Instant::now();
        let mut causes = [0; 9];
        causes[0] = 1;
        assert!(repeats.causes_changed(causes));
        repeats.observe(&[confirm(1, 5)], 5, now);
        assert!(!repeats.causes_changed(causes));
        causes[1] = 1;
        assert!(repeats.causes_changed(causes));
        repeats.observe(&[], 6, now);
        assert!(repeats.causes_changed(causes), "a later leave speaks again");
    }
}
