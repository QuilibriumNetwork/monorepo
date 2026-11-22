//! QUILIBRIUM: f+1 certificate broadcasters.
//!
//! Upstream, every member broadcasts every certificate it holds, built from
//! votes or received: each certificate of a view goes out once per member.
//! Here only `max(f+1, 2)` members per view (capped at the committee size)
//! broadcast at once. They are the first in the participant order from the
//! round-robin leader of the view, counting first the members heard voting
//! within the last [`Timing::heard_views`] views (a member always counts
//! itself), then the others: a member that sends nothing is not picked while
//! enough members are heard, so its slot does not cost a fallback each view.
//!
//! Each member decides from the votes it received, so members can disagree
//! on who was heard. That only changes when a copy goes out: two members may
//! both send at once (an extra copy), or fewer than `f+1` may (the deferred
//! fallback below sends instead). No certificate is lost: every holder that
//! is not selected keeps its fallback until `f+1` distinct copies reached it.
//!
//! Any other member holding a certificate defers it: it sends at
//! [`Timing::delay`] plus [`Timing::step`] times its position after the
//! selected members (capped at [`Timing::latest`]), unless copies from `f+1` distinct members (itself
//! excluded) arrived first. At most `f` members are faulty, so `f+1` distinct
//! senders include an honest one, and an honest sender sends to everyone. A
//! held finalization also cancels the view's deferred notarization. With `k`
//! selected members offline about `k` deferred copies go out, not one per
//! member: each copy that lands raises every other member's count.
//!
//! Only the certificate of the view itself takes the rule; the nullify-retry
//! entry, the skipped proposer's floor and the fallback-proposal
//! nullifications are sent as before. Votes and the resolver are unchanged.

use crate::{
    simplex::types::Certificate,
    types::{Epoch, Participant, View},
};
use commonware_cryptography::{certificate::Scheme, Digest};
use commonware_utils::{Faults, N3f1};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, SystemTime},
};

/// How often the fan-out counters are logged.
pub(crate) const SUMMARY_EVERY: Duration = Duration::from_secs(600);

/// The certificate kinds of a view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Kind {
    Notarization = 0,
    Nullification = 1,
    Finalization = 2,
}

impl Kind {
    /// The kind of `certificate`.
    pub(crate) const fn of<S: Scheme, D: Digest>(certificate: &Certificate<S, D>) -> Self {
        match certificate {
            Certificate::Notarization(_) => Self::Notarization,
            Certificate::Nullification(_) => Self::Nullification,
            Certificate::Finalization(_) => Self::Finalization,
        }
    }

    const fn index(self) -> usize {
        self as usize
    }
}

/// Members that broadcast a view's certificates at once: `max(f+1, 2)`,
/// capped at `n`. The floor of 2 covers committees of three or fewer (`f = 0`).
pub(crate) fn broadcaster_count(n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    (N3f1::max_faults(n) + 1).max(2).min(n)
}

/// `None` when `member` broadcasts the certificates of `view` at once;
/// otherwise its rank among the deferred members (0 sends first).
///
/// Members are taken in the participant order from the round-robin leader of
/// the view, `(epoch + view) mod n` (as [`crate::simplex::elector::RoundRobin`]
/// unseeded): first those `heard` (indexed by member), then the rest. The
/// first [`broadcaster_count`] are selected; a member never heard ranks after
/// every heard one.
pub(crate) fn fallback_rank(
    epoch: Epoch,
    view: View,
    n: u32,
    member: u32,
    heard: &[bool],
) -> Option<u32> {
    if n == 0 {
        return None;
    }
    let start = epoch.get().wrapping_add(view.get()) % u64::from(n);
    let rotation = (0..u64::from(n)).map(|i| ((start + i) % u64::from(n)) as u32);
    let is_heard = |m: u32| heard.get(m as usize).copied().unwrap_or(false);
    let position = rotation
        .clone()
        .filter(|&m| is_heard(m))
        .chain(rotation.filter(|&m| !is_heard(m)))
        .position(|m| m == member % n)? as u32;
    position.checked_sub(broadcaster_count(n))
}

/// When deferred certificates go out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// Wait before the first deferred member sends.
    pub delay: Duration,
    /// Extra wait per rank after the first deferred member.
    pub step: Duration,
    /// Cap on any deferred wait, so the last fallback still goes out before
    /// the resolver's fetch would.
    pub latest: Duration,
    /// A member counts as heard for a view when it sent a vote for this view
    /// or one of the `heard_views - 1` views before it.
    pub heard_views: u64,
}

impl Timing {
    /// The one place the waits are derived: half of the resolver's
    /// `fetch_timeout` (the next protection for a member missing a
    /// certificate), and a twentieth of it per rank, capped one step before
    /// `fetch_timeout`. Heard: a vote within the last 20 views (four times
    /// the engine's `skip_timeout` of 5); a member silent for hours drops
    /// out, a member missing a few views stays in.
    pub fn from_fetch_timeout(fetch_timeout: Duration) -> Self {
        let step = fetch_timeout / 20;
        Self {
            delay: fetch_timeout / 2,
            step,
            latest: fetch_timeout.saturating_sub(step),
            heard_views: 20,
        }
    }

    fn wait(&self, rank: u32) -> Duration {
        self.delay
            .saturating_add(self.step.saturating_mul(rank))
            .min(self.latest)
    }
}

#[derive(Default)]
struct Ledger {
    senders: BTreeMap<(View, Kind), BTreeSet<u32>>,
    unknown: [u64; 3],
    /// The highest view each member was heard voting for.
    voted: BTreeMap<u32, View>,
}

/// Distinct members a copy of each held certificate came from, filled by the
/// batcher (which drops copies it already holds before the voter sees them)
/// and read by the voter.
#[derive(Default)]
pub struct Copies {
    ledger: Mutex<Ledger>,
}

impl Copies {
    fn ledger(&self) -> std::sync::MutexGuard<'_, Ledger> {
        self.ledger.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records a copy of the `kind` certificate of `view` from `sender`
    /// (`None`: a sender outside the committee, which never cancels).
    pub(crate) fn record(&self, view: View, kind: Kind, sender: Option<Participant>) {
        let mut ledger = self.ledger();
        match sender {
            Some(sender) => {
                ledger
                    .senders
                    .entry((view, kind))
                    .or_default()
                    .insert(sender.get());
            }
            None => ledger.unknown[kind.index()] += 1,
        }
    }

    /// Records a vote for `view` from committee member `sender`.
    pub(crate) fn record_vote(&self, view: View, sender: Participant) {
        let mut ledger = self.ledger();
        let latest = ledger.voted.entry(sender.get()).or_insert(view);
        if *latest < view {
            *latest = view;
        }
    }

    /// Per member of `n`: heard voting for `view` or one of the `window - 1`
    /// views before it (a vote for a later view counts too).
    pub(crate) fn heard(&self, view: View, window: u64, n: u32) -> Vec<bool> {
        let ledger = self.ledger();
        (0..n)
            .map(|member| {
                ledger
                    .voted
                    .get(&member)
                    .is_some_and(|voted| view.get().saturating_sub(voted.get()) < window)
            })
            .collect()
    }

    /// Distinct members a copy of the `kind` certificate of `view` came from.
    pub(crate) fn senders(&self, view: View, kind: Kind) -> usize {
        self.ledger()
            .senders
            .get(&(view, kind))
            .map_or(0, BTreeSet::len)
    }

    fn take_unknown(&self) -> [u64; 3] {
        std::mem::take(&mut self.ledger().unknown)
    }

    fn prune(&self, min: View) {
        let mut ledger = self.ledger();
        let kept = ledger.senders.split_off(&(min, Kind::Notarization));
        ledger.senders = kept;
    }
}

/// Fan-out counters per kind (notarization, nullification, finalization)
/// since the last summary.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Summary {
    /// Seconds since the previous summary (since the first count for the first).
    pub secs: u64,
    /// Sent at once as a selected member.
    pub selected_sent: [u64; 3],
    /// Held as a non-selected member.
    pub deferred: [u64; 3],
    /// Deferred and sent at the deadline.
    pub fallback_fired: [u64; 3],
    /// Deferred and never sent: `f+1` members (or a finalization) were first.
    pub fallback_cancelled: [u64; 3],
    /// Copies from senders outside the committee.
    pub unknown_sender_copies: [u64; 3],
    /// Members not heard voting recently, ranked after the heard ones, summed
    /// over the certificates taken.
    pub silent_skipped: [u64; 3],
}

impl Summary {
    /// `notarization/nullification/finalization`.
    pub(crate) fn per_kind(counts: &[u64; 3]) -> String {
        format!("{}/{}/{}", counts[0], counts[1], counts[2])
    }

    fn is_empty(&self) -> bool {
        [
            &self.selected_sent,
            &self.deferred,
            &self.fallback_fired,
            &self.fallback_cancelled,
            &self.unknown_sender_copies,
            &self.silent_skipped,
        ]
        .iter()
        .all(|counts| counts.iter().all(|&count| count == 0))
    }
}

/// One member's deferred certificates.
pub(crate) struct Fanout<C> {
    timing: Timing,
    copies: Arc<Copies>,
    participants: u32,
    me: Option<u32>,
    deferred: BTreeMap<(View, Kind), (SystemTime, C)>,
    counts: Summary,
    since: Option<SystemTime>,
}

impl<C> Fanout<C> {
    /// `me` is this member's participant index (`None` for an observer,
    /// which defers behind every member).
    pub(crate) const fn new(
        timing: Timing,
        copies: Arc<Copies>,
        participants: u32,
        me: Option<u32>,
    ) -> Self {
        Self {
            timing,
            copies,
            participants,
            me,
            deferred: BTreeMap::new(),
            counts: Summary {
                secs: 0,
                selected_sent: [0; 3],
                deferred: [0; 3],
                fallback_fired: [0; 3],
                fallback_cancelled: [0; 3],
                unknown_sender_copies: [0; 3],
                silent_skipped: [0; 3],
            },
            since: None,
        }
    }

    /// Copies from this many distinct members cancel a deferred certificate.
    fn cancel_at(&self) -> usize {
        N3f1::max_faults(self.participants) as usize + 1
    }

    fn cancelled(&self, view: View, kind: Kind, finalized: bool) -> bool {
        (kind == Kind::Notarization && finalized)
            || self.copies.senders(view, kind) >= self.cancel_at()
    }

    /// Takes a certificate this member now holds. Returns it when it goes out
    /// at once, `None` when it is deferred or no longer needed. `finalized`:
    /// this member holds a finalization of `view`.
    pub(crate) fn stage(
        &mut self,
        epoch: Epoch,
        view: View,
        kind: Kind,
        certificate: C,
        now: SystemTime,
        finalized: bool,
    ) -> Option<C> {
        self.since.get_or_insert(now);
        let n = self.participants;
        let rank = match self.me {
            Some(me) => {
                let mut heard = self.copies.heard(view, self.timing.heard_views, n);
                if let Some(mine) = heard.get_mut(me as usize) {
                    *mine = true;
                }
                let silent = heard.iter().filter(|&&heard| !heard).count() as u64;
                self.counts.silent_skipped[kind.index()] += silent;
                fallback_rank(epoch, view, n, me, &heard)
            }
            None => Some(n - broadcaster_count(n)),
        };
        let Some(rank) = rank else {
            self.counts.selected_sent[kind.index()] += 1;
            return Some(certificate);
        };
        self.counts.deferred[kind.index()] += 1;
        if self.cancelled(view, kind, finalized) {
            self.counts.fallback_cancelled[kind.index()] += 1;
            return None;
        }
        let deadline = now + self.timing.wait(rank);
        self.deferred.insert((view, kind), (deadline, certificate));
        None
    }

    /// The earliest deferred deadline.
    pub(crate) fn next_deadline(&self) -> Option<SystemTime> {
        self.deferred.values().map(|(deadline, _)| *deadline).min()
    }

    /// Removes every deferred certificate due at `now`, returning those to
    /// send. `finalized(view)`: this member holds a finalization of `view`.
    pub(crate) fn due(&mut self, now: SystemTime, finalized: impl Fn(View) -> bool) -> Vec<C> {
        let due: Vec<(View, Kind)> = self
            .deferred
            .iter()
            .filter(|(_, (deadline, _))| *deadline <= now)
            .map(|(key, _)| *key)
            .collect();
        let mut send = Vec::new();
        for (view, kind) in due {
            let Some((_, certificate)) = self.deferred.remove(&(view, kind)) else {
                continue;
            };
            if self.cancelled(view, kind, finalized(view)) {
                self.counts.fallback_cancelled[kind.index()] += 1;
            } else {
                self.counts.fallback_fired[kind.index()] += 1;
                send.push(certificate);
            }
        }
        send
    }

    /// Drops deferred certificates and copy counts of views below `min`.
    pub(crate) fn prune(&mut self, min: View) {
        self.deferred = self.deferred.split_off(&(min, Kind::Notarization));
        self.copies.prune(min);
    }

    /// The `(view, kind)` entries held: a copy count or a deferred
    /// certificate. Only [`Self::prune`] removes copy counts, so this stays
    /// within the active views only while the voter prunes.
    pub(crate) fn tracked(&self) -> usize {
        let ledger = self.copies.ledger();
        let deferred_only = self
            .deferred
            .keys()
            .filter(|key| !ledger.senders.contains_key(key))
            .count();
        ledger.senders.len() + deferred_only
    }

    /// The counters since the last summary, once per [`SUMMARY_EVERY`] when
    /// any is non-zero.
    pub(crate) fn summary(&mut self, now: SystemTime) -> Option<Summary> {
        let since = *self.since.get_or_insert(now);
        let elapsed = now.duration_since(since).unwrap_or_default();
        if elapsed < SUMMARY_EVERY {
            return None;
        }
        let unknown = self.copies.take_unknown();
        for (total, more) in self.counts.unknown_sender_copies.iter_mut().zip(unknown) {
            *total += more;
        }
        self.since = Some(now);
        let mut summary = std::mem::take(&mut self.counts);
        if summary.is_empty() {
            return None;
        }
        summary.secs = elapsed.as_secs();
        Some(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH: Epoch = Epoch::new(333);

    fn t(ms: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_millis(ms)
    }

    fn timing() -> Timing {
        Timing::from_fetch_timeout(Duration::from_secs(5))
    }

    fn selected(view: View, n: u32) -> Vec<u32> {
        (0..n)
            .filter(|&member| fallback_rank(EPOCH, view, n, member, &all(n)).is_none())
            .collect()
    }

    fn by_rank(view: View, n: u32) -> Vec<u32> {
        let mut deferred: Vec<(u32, u32)> = (0..n)
            .filter_map(|member| fallback_rank(EPOCH, view, n, member, &all(n)).map(|rank| (rank, member)))
            .collect();
        deferred.sort_unstable();
        deferred.into_iter().map(|(_, member)| member).collect()
    }

    fn all(n: u32) -> Vec<bool> {
        vec![true; n as usize]
    }

    /// Records a vote from each of `members` far ahead, so they count as
    /// heard for every view the tests use.
    fn hear(copies: &Copies, members: impl IntoIterator<Item = u32>) {
        for member in members {
            copies.record_vote(View::new(1 << 40), Participant::new(member));
        }
    }

    /// Member `me` of `n` that heard every member vote.
    fn member(copies: &Arc<Copies>, n: u32, me: u32) -> Fanout<&'static str> {
        hear(copies, 0..n);
        Fanout::new(timing(), copies.clone(), n, Some(me))
    }

    #[test]
    fn broadcasters_are_f_plus_one_from_the_leader() {
        for n in [1u32, 2, 3, 4, 7, 15, 34] {
            let f = N3f1::max_faults(n);
            let b = (f + 1).max(2).min(n);
            assert_eq!(broadcaster_count(n), b, "n={n}");
            for view in 1..=(2 * u64::from(n)) {
                let view = View::new(view);
                let set = selected(view, n);
                assert_eq!(set.len() as u32, b, "n={n} view={view}");
                let leader = (EPOCH.get().wrapping_add(view.get()) % u64::from(n)) as u32;
                let expected: Vec<u32> = {
                    let mut ids: Vec<u32> = (0..b).map(|k| (leader + k) % n).collect();
                    ids.sort_unstable();
                    ids
                };
                assert_eq!(set, expected, "n={n} view={view}");
                let ranks: BTreeSet<u32> = (0..n)
                    .filter_map(|member| fallback_rank(EPOCH, view, n, member, &all(n)))
                    .collect();
                assert_eq!(ranks, (0..n - b).collect(), "n={n} view={view}");
            }
            // The set rotates with the view.
            if n > b {
                assert_ne!(
                    selected(View::new(1), n),
                    selected(View::new(2), n),
                    "n={n}"
                );
            }
        }
    }

    #[test]
    fn selected_member_sends_at_once() {
        let copies = Arc::new(Copies::default());
        let view = View::new(10);
        let me = selected(view, 15)[0];
        let mut fanout = member(&copies, 15, me);
        let sent = fanout.stage(EPOCH, view, Kind::Notarization, "cert", t(0), false);
        assert_eq!(sent, Some("cert"));
        assert_eq!(fanout.next_deadline(), None);
    }

    #[test]
    fn non_selected_sends_nothing_before_the_delay() {
        let copies = Arc::new(Copies::default());
        let view = View::new(10);
        let me = by_rank(view, 15)[0];
        let mut fanout = member(&copies, 15, me);
        assert_eq!(
            fanout.stage(EPOCH, view, Kind::Notarization, "cert", t(0), false),
            None
        );
        let delay = timing().delay.as_millis() as u64;
        assert_eq!(fanout.next_deadline(), Some(t(delay)));
        assert!(fanout.due(t(delay - 1), |_| false).is_empty());
        assert_eq!(fanout.due(t(delay), |_| false), vec!["cert"]);
        assert_eq!(fanout.next_deadline(), None);
    }

    #[test]
    fn all_selected_offline_still_sends() {
        // No copies at all: every deferred member fires at its own deadline.
        let copies = Arc::new(Copies::default());
        let view = View::new(4);
        let n = 7;
        let timing = timing();
        for (rank, me) in by_rank(view, n).into_iter().enumerate() {
            let mut fanout = member(&copies, n, me);
            fanout.stage(EPOCH, view, Kind::Finalization, "cert", t(0), true);
            let wait = timing.wait(rank as u32);
            assert_eq!(fanout.next_deadline(), Some(t(0) + wait), "rank {rank}");
            assert_eq!(
                fanout.due(t(0) + wait, |_| true),
                vec!["cert"],
                "rank {rank}"
            );
        }
    }

    #[test]
    fn cancels_only_at_f_plus_one_distinct_senders() {
        let n = 15;
        let f = N3f1::max_faults(n);
        let view = View::new(10);
        let me = by_rank(view, n)[0];
        let others: Vec<u32> = (0..n).filter(|&member| member != me).collect();

        // f faulty members, one of them repeating its copy: never cancels.
        let copies = Arc::new(Copies::default());
        let mut fanout = member(&copies, n, me);
        fanout.stage(EPOCH, view, Kind::Nullification, "cert", t(0), false);
        for &sender in &others[..f as usize] {
            for _ in 0..3 {
                copies.record(view, Kind::Nullification, Some(Participant::new(sender)));
            }
        }
        // A copy from outside the committee never counts.
        copies.record(view, Kind::Nullification, None);
        // Copies of another kind or view never count.
        copies.record(
            view,
            Kind::Notarization,
            Some(Participant::new(others[f as usize])),
        );
        copies.record(
            view.next(),
            Kind::Nullification,
            Some(Participant::new(others[f as usize])),
        );
        assert_eq!(copies.senders(view, Kind::Nullification), f as usize);
        let deadline = fanout.next_deadline().unwrap();
        assert_eq!(fanout.due(deadline, |_| false), vec!["cert"]);

        // f+1 distinct members cancel.
        let copies = Arc::new(Copies::default());
        let mut fanout = member(&copies, n, me);
        fanout.stage(EPOCH, view, Kind::Nullification, "cert", t(0), false);
        for &sender in &others[..=f as usize] {
            copies.record(view, Kind::Nullification, Some(Participant::new(sender)));
        }
        let deadline = fanout.next_deadline().unwrap();
        assert!(fanout.due(deadline, |_| false).is_empty());

        // Already f+1 when the certificate is staged: never deferred.
        assert_eq!(
            fanout.stage(EPOCH, view, Kind::Nullification, "cert", t(0), false),
            None
        );
        assert_eq!(fanout.next_deadline(), None);
        let summary = fanout.summary(t(0) + SUMMARY_EVERY).unwrap();
        assert_eq!(summary.deferred, [0, 2, 0]);
        assert_eq!(summary.fallback_cancelled, [0, 2, 0]);
    }

    #[test]
    fn finalization_cancels_the_deferred_notarization() {
        let copies = Arc::new(Copies::default());
        let view = View::new(10);
        let me = by_rank(view, 7)[0];
        let mut fanout = member(&copies, 7, me);
        fanout.stage(EPOCH, view, Kind::Notarization, "notarization", t(0), false);
        let deadline = fanout.next_deadline().unwrap();
        assert!(fanout.due(deadline, |held| held == view).is_empty());
        assert_eq!(
            fanout.stage(EPOCH, view, Kind::Notarization, "notarization", t(0), true),
            None
        );
        assert_eq!(fanout.next_deadline(), None);
    }

    /// Every member holds the certificate at time 0; copies land 10 ms after
    /// they are sent. Returns the deferred copies sent.
    /// Fallbacks fired for one view with `offline` members sending nothing;
    /// `offline_heard`: they were heard voting before.
    fn simulate(n: u32, offline: &[u32], offline_heard: bool) -> usize {
        let view = View::new(10);
        let latency = 10;
        let ledgers: Vec<Arc<Copies>> = (0..n).map(|_| Arc::new(Copies::default())).collect();
        for ledger in &ledgers {
            hear(
                ledger,
                (0..n).filter(|member| offline_heard || !offline.contains(member)),
            );
        }
        let mut fanouts: Vec<Fanout<u32>> = (0..n)
            .map(|me| Fanout::new(timing(), ledgers[me as usize].clone(), n, Some(me)))
            .collect();
        let mut in_flight: Vec<(u64, u32)> = Vec::new();
        for me in (0..n).filter(|me| !offline.contains(me)) {
            if let Some(sender) =
                fanouts[me as usize].stage(EPOCH, view, Kind::Finalization, me, t(0), true)
            {
                in_flight.push((latency, sender));
            }
        }
        let mut fired = 0;
        let end = timing().wait(n).as_millis() as u64;
        for now in 0..=end {
            for &(_, sender) in in_flight.iter().filter(|(at, _)| *at == now) {
                for (member, ledger) in ledgers.iter().enumerate() {
                    if member as u32 != sender {
                        ledger.record(view, Kind::Finalization, Some(Participant::new(sender)));
                    }
                }
            }
            for me in (0..n).filter(|me| !offline.contains(me)) {
                for sender in fanouts[me as usize].due(t(now), |_| true) {
                    fired += 1;
                    in_flight.push((now + latency, sender));
                }
            }
        }
        fired
    }

    #[test]
    fn selected_offline_gives_one_deferred_copy_each() {
        for n in [7u32, 15] {
            let view = View::new(10);
            let f = N3f1::max_faults(n) as usize;
            assert_eq!(simulate(n, &[], true), 0, "n={n}");
            for down in 1..=f {
                let offline = &selected(view, n)[..down];
                assert_eq!(simulate(n, offline, true), down, "n={n} offline={offline:?}");
            }
        }
    }

    #[test]
    fn silent_members_cost_no_fallback() {
        for n in [7u32, 15, 35] {
            let view = View::new(10);
            let f = N3f1::max_faults(n) as usize;
            for down in 1..=f {
                // The members selected were every member heard, never heard.
                let offline = &selected(view, n)[..down];
                assert_eq!(simulate(n, offline, false), 0, "n={n} offline={offline:?}");
            }
        }
    }

    #[test]
    fn never_heard_members_rank_after_every_heard_one() {
        let (n, view) = (35u32, View::new(10));
        let b = broadcaster_count(n);
        let mut heard = all(n);
        let silent = selected(view, n);
        for &member in &silent[..6] {
            heard[member as usize] = false;
        }
        let ranks: Vec<Option<u32>> = (0..n)
            .map(|member| fallback_rank(EPOCH, view, n, member, &heard))
            .collect();
        assert_eq!(ranks.iter().filter(|rank| rank.is_none()).count() as u32, b);
        for member in 0..n {
            if !heard[member as usize] {
                assert!(ranks[member as usize] >= Some(n - b - 6), "member {member}");
            }
        }
        // Nobody heard: the rotation alone decides, as with everyone heard.
        for member in 0..n {
            assert_eq!(
                fallback_rank(EPOCH, view, n, member, &vec![false; n as usize]),
                fallback_rank(EPOCH, view, n, member, &all(n)),
            );
        }
    }

    #[test]
    fn heard_only_within_the_window() {
        let copies = Copies::default();
        let window = timing().heard_views;
        copies.record_vote(View::new(10), Participant::new(1));
        copies.record_vote(View::new(4), Participant::new(1));
        assert_eq!(copies.heard(View::new(9 + window), window, 3), [false, true, false]);
        assert_eq!(copies.heard(View::new(10 + window), window, 3), [false; 3]);
    }

    #[test]
    fn last_fallback_lands_before_the_fetch_timeout() {
        let fetch_timeout = Duration::from_secs(5);
        let timing = Timing::from_fetch_timeout(fetch_timeout);
        assert_eq!(timing.wait(0), Duration::from_millis(2500));
        assert_eq!(timing.wait(1), Duration::from_millis(2750));
        // n = 35: ranks up to 22 would reach 8 s uncapped.
        for rank in 0..35 {
            assert!(timing.wait(rank) < fetch_timeout, "rank {rank}");
        }
        assert_eq!(timing.wait(22), Duration::from_millis(4750));
    }

    #[test]
    fn summary_every_ten_minutes() {
        let copies = Arc::new(Copies::default());
        let view = View::new(10);
        let me = selected(view, 7)[0];
        let mut fanout = member(&copies, 7, me);
        assert_eq!(fanout.summary(t(0)), None);
        fanout.stage(EPOCH, view, Kind::Finalization, "cert", t(1), true);
        copies.record(view, Kind::Notarization, None);
        let at = t(0) + SUMMARY_EVERY;
        assert_eq!(fanout.summary(at - Duration::from_millis(1)), None);
        let summary = fanout.summary(at).unwrap();
        assert_eq!(summary.secs, SUMMARY_EVERY.as_secs());
        assert_eq!(summary.selected_sent, [0, 0, 1]);
        assert_eq!(summary.unknown_sender_copies, [1, 0, 0]);
        assert_eq!(Summary::per_kind(&summary.selected_sent), "0/0/1");
        // Nothing counted since: no line.
        assert_eq!(fanout.summary(at + SUMMARY_EVERY), None);
    }

    #[test]
    fn prune_drops_old_views() {
        let copies = Arc::new(Copies::default());
        let view = View::new(10);
        let me = by_rank(view, 7)[0];
        let mut fanout = member(&copies, 7, me);
        fanout.stage(EPOCH, view, Kind::Nullification, "cert", t(0), false);
        copies.record(view, Kind::Nullification, Some(Participant::new(me + 1)));
        // A deferral with no copy yet, and a copy of a later view.
        fanout.stage(EPOCH, view, Kind::Notarization, "cert", t(0), false);
        copies.record(view.next(), Kind::Finalization, Some(Participant::new(me + 1)));
        assert_eq!(fanout.tracked(), 3);
        fanout.prune(view);
        assert!(fanout.next_deadline().is_some());
        assert_eq!(copies.senders(view, Kind::Nullification), 1);
        assert_eq!(fanout.tracked(), 3);
        fanout.prune(view.next());
        assert_eq!(fanout.next_deadline(), None);
        assert_eq!(copies.senders(view, Kind::Nullification), 0);
        assert_eq!(fanout.tracked(), 1);
        fanout.prune(view.next().next());
        assert_eq!(fanout.tracked(), 0);
    }
}
