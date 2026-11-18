//! Owns partition timing: the per-view schedule plus the state tracking which of
//! its entries have actually been applied.
//!
//! The schedule is a point trigger with an implicit heal — an entry applies when
//! its view is observed, and the first observed view with no entry clears every
//! partition. Repeating an entry on consecutive views is how a partition is held
//! open.
//!
//! This lives apart from the proxy's event loop for two reasons:
//!
//! * **The transition must be atomic with the message that caused it.** The gRPC
//!   snoop applies the schedule inline, before its own partition gate, so the
//!   very message that revealed a view is subject to the partition it triggers.
//!   Routing the view through the event-loop channel instead would let that
//!   message — and every concurrent fan-out copy of it — forward against the
//!   pre-transition state.
//! * **A schedule entry that never fired invalidates the run.** [`Self::missed_views`]
//!   is the authoritative record, so a run that failed to partition fails loudly
//!   instead of reporting a pass.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use devnet::viewpartitions::ViewPartitionEntry;

use crate::partitioner::NetworkPartitioner;

/// Mutable schedule state. Kept behind one lock so the monotone check and the
/// partition swap are indivisible against the other listener tasks.
#[derive(Debug, Default)]
struct State {
    /// Highest view acted on. Views only move forward, so this both dedupes (a
    /// message is snooped once per backend listener, and a partitioned send is
    /// retried after the UNAVAILABLE response) and stops a late-arriving older
    /// view from undoing newer partition state.
    highest_view: Option<u64>,
    /// Scheduled views whose entry was applied.
    applied: BTreeSet<u64>,
}

pub struct ViewSchedule {
    entries: HashMap<u64, ViewPartitionEntry>,
    partitioner: Arc<NetworkPartitioner>,
    state: Mutex<State>,
}

impl ViewSchedule {
    pub fn new(
        entries: HashMap<u64, ViewPartitionEntry>,
        partitioner: Arc<NetworkPartitioner>,
    ) -> Self {
        Self {
            entries,
            partitioner,
            state: Mutex::new(State::default()),
        }
    }

    /// Apply a view-0 entry, if the schedule has one, before consensus starts.
    ///
    /// Simplex views start at 1, so no message ever carries view 0 — a view-0
    /// entry means "partitioned before consensus starts" and has to be applied
    /// eagerly or it could never fire.
    pub fn apply_initial(&self) {
        let Some(entry) = self.entries.get(&0) else {
            return;
        };
        let mut state = self.state.lock().expect("schedule mutex poisoned");
        tracing::info!(view = 0, "applying view partition before consensus starts");
        self.partitioner
            .apply_partition(&entry.partition1, &entry.partition2);
        state.applied.insert(0);
    }

    /// Apply (or clear) the partition for `view`, once, in view order.
    ///
    /// Callers must invoke this *before* consulting the partition gate for the
    /// message that carried `view`.
    pub fn observe_view(&self, view: u64) {
        if self.entries.is_empty() {
            return;
        }
        let mut state = self.state.lock().expect("schedule mutex poisoned");
        if state.highest_view.is_some_and(|prev| view <= prev) {
            return;
        }
        state.highest_view = Some(view);

        match self.entries.get(&view) {
            Some(entry) => {
                tracing::info!(view, "applying view partition");
                self.partitioner
                    .apply_partition(&entry.partition1, &entry.partition2);
                state.applied.insert(view);
            }
            None => {
                tracing::info!(view, "no view partition entry, clearing partitions");
                self.partitioner.clear_partitions();
            }
        }
    }

    /// Scheduled views that were never applied, ascending.
    ///
    /// A non-empty result means the run did not execute the scenario it was
    /// given — the proxy never observed those views — so its verdict is not
    /// evidence of anything. Unlike a gap check against the last-seen view, this
    /// also catches an entry below the first view the proxy ever observed.
    pub fn missed_views(&self) -> Vec<u64> {
        let state = self.state.lock().expect("schedule mutex poisoned");
        let mut missed: Vec<u64> = self
            .entries
            .keys()
            .copied()
            .filter(|v| !state.applied.contains(v))
            .collect();
        missed.sort_unstable();
        missed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_p2p::ed448_identity::Ed448Identity;
    use quil_p2p::PeerId;
    use std::str::FromStr;

    /// Two distinct peers, as both parsed IDs and the base58 strings the
    /// schedule entries carry.
    fn peers() -> (PeerId, String, PeerId, String) {
        let a58 = Ed448Identity::generate().unwrap().peer_id_base58();
        let b58 = Ed448Identity::generate().unwrap().peer_id_base58();
        let a = PeerId::from_str(&a58).unwrap();
        let b = PeerId::from_str(&b58).unwrap();
        (a, a58, b, b58)
    }

    fn schedule(views: &[u64], a58: &str, b58: &str) -> (Arc<NetworkPartitioner>, ViewSchedule) {
        let entries = views
            .iter()
            .map(|&view| {
                (
                    view,
                    ViewPartitionEntry {
                        view,
                        partition1: vec![a58.to_string()],
                        partition2: vec![b58.to_string()],
                    },
                )
            })
            .collect();
        let partitioner = Arc::new(NetworkPartitioner::new());
        let sched = ViewSchedule::new(entries, Arc::clone(&partitioner));
        (partitioner, sched)
    }

    #[test]
    fn applies_at_its_view_then_heals_implicitly() {
        let (a, a58, b, b58) = peers();
        let (p, sched) = schedule(&[3], &a58, &b58);

        sched.observe_view(2);
        assert!(p.forward_filter(&a, &b), "no entry at view 2");

        sched.observe_view(3);
        assert!(!p.forward_filter(&a, &b), "entry at view 3 must partition");

        sched.observe_view(4);
        assert!(p.forward_filter(&a, &b), "view 4 has no entry, so it heals");
        assert!(sched.missed_views().is_empty());
    }

    #[test]
    fn repeated_entries_hold_the_partition_across_views() {
        let (a, a58, b, b58) = peers();
        let (p, sched) = schedule(&[3, 4, 5], &a58, &b58);

        for view in 3..=5 {
            sched.observe_view(view);
            assert!(
                !p.forward_filter(&a, &b),
                "still partitioned at view {view}"
            );
        }
        sched.observe_view(6);
        assert!(p.forward_filter(&a, &b), "heals after the last entry");
        assert!(sched.missed_views().is_empty());
    }

    /// One message is snooped once per backend listener, and a partitioned send
    /// is retried after the UNAVAILABLE response, so repeats are routine.
    #[test]
    fn repeated_observations_are_idempotent() {
        let (a, a58, b, b58) = peers();
        let (p, sched) = schedule(&[3], &a58, &b58);

        for _ in 0..5 {
            sched.observe_view(3);
        }
        assert!(!p.forward_filter(&a, &b));
    }

    #[test]
    fn stale_view_does_not_undo_newer_state() {
        let (a, a58, b, b58) = peers();
        let (p, sched) = schedule(&[3], &a58, &b58);

        sched.observe_view(3);
        sched.observe_view(4);
        assert!(p.forward_filter(&a, &b), "healed at view 4");

        sched.observe_view(3);
        assert!(
            p.forward_filter(&a, &b),
            "a stale view-3 observation must not re-partition"
        );
    }

    #[test]
    fn empty_schedule_never_touches_the_partitioner() {
        let (a, a58, b, b58) = peers();
        let partitioner = Arc::new(NetworkPartitioner::new());
        partitioner.apply_partition(&[a58], &[b58]);
        let sched = ViewSchedule::new(HashMap::new(), Arc::clone(&partitioner));

        sched.observe_view(7);
        assert!(
            !partitioner.forward_filter(&a, &b),
            "pre-existing state must be left alone"
        );
        assert!(sched.missed_views().is_empty());
    }

    #[test]
    fn view_zero_entry_applies_eagerly_and_counts_as_applied() {
        let (a, a58, b, b58) = peers();
        let (p, sched) = schedule(&[0], &a58, &b58);

        sched.apply_initial();
        assert!(!p.forward_filter(&a, &b), "view 0 applies before consensus");
        assert!(
            sched.missed_views().is_empty(),
            "an eagerly applied entry must not read as missed"
        );

        sched.observe_view(1);
        assert!(p.forward_filter(&a, &b), "view 1 has no entry, so it heals");
    }

    #[test]
    fn unobserved_view_is_reported_missed() {
        let (_, a58, _, b58) = peers();
        let (_p, sched) = schedule(&[3, 5], &a58, &b58);

        sched.observe_view(3);
        sched.observe_view(4);
        sched.observe_view(6); // view 5 was never seen
        assert_eq!(sched.missed_views(), vec![5]);
    }

    /// The case a gap check against the last-seen view structurally cannot
    /// catch: the entry sits below the first view the proxy ever observed, so
    /// there is no previous view to measure a gap from.
    #[test]
    fn entry_below_the_first_observed_view_is_reported_missed() {
        let (_, a58, _, b58) = peers();
        let (_p, sched) = schedule(&[1], &a58, &b58);

        sched.observe_view(4);
        assert_eq!(sched.missed_views(), vec![1]);
    }

    #[test]
    fn missed_views_are_sorted() {
        let (_, a58, _, b58) = peers();
        let (_p, sched) = schedule(&[7, 2, 4], &a58, &b58);

        sched.observe_view(9);
        assert_eq!(sched.missed_views(), vec![2, 4, 7]);
    }
}
