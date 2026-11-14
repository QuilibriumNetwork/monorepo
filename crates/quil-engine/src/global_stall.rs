//! Operator signals for GLOBAL consensus on a GLOBAL prover: which GLOBAL
//! provers this node hears, for the node's GLOBAL progress condition, and a
//! bounded count of the leader turns that pass without a proposal.
//!
//! A halted GLOBAL committee logs little on its live members: transport
//! warnings about the missing members and routine status lines. The node's
//! health registry (`quil_rpc::health_conditions`) judges on every node
//! whether the GLOBAL head advances, logs that condition and serves it. On a
//! GLOBAL prover [`GlobalWatch`] adds what only a member knows ([`reach`]):
//! the GLOBAL provers heard from recently against the quorum consensus
//! needs, the silent ones, and the stall window its leader timeout implies,
//! so the condition says whether GLOBAL lacks the members its quorum needs.
//!
//! A leader turn passes without a proposal when its view is nullified and no
//! member voted for any proposal in it: the leader stopped, is unreachable,
//! or could not build one. Consensus moves on after its leader timeout,
//! silently. [`GlobalWatch`] counts those turns per leader and logs them at
//! most every [`SKIP_REPORT_EVERY`].
//!
//! Logging state only: nothing here feeds consensus.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use quil_cw_consensus::adapters::{Liveness, ViewSigners};
use quil_cw_consensus::falcon_base::FalconPublicKey;

/// How often the watch looks at consensus.
pub const CHECK_EVERY: Duration = Duration::from_secs(10);
/// The shortest GLOBAL stall. A frame takes about 10 s
/// ([`crate::difficulty::IDEAL_FRAME_TIME`]); a leader turn without a
/// proposal adds a leader timeout (30 s by default). A stall needs four
/// leader timeouts and at least this, so three consecutive skipped turns and
/// a frame are not one.
pub const MIN_STALL_AFTER: Duration = Duration::from_secs(120);
/// A published [`GlobalReach`] older than this is not served: the watch
/// stopped.
const REACH_FRESH: Duration = Duration::from_secs(30);
/// How often skipped leader turns are logged at most.
pub const SKIP_REPORT_EVERY: Duration = Duration::from_secs(600);
/// A member counts as reachable when a consensus message of it arrived this
/// recently, or within four vote rebroadcast intervals if that is longer:
/// while a view is stuck, every live member rebroadcasts its vote once per
/// interval (15 s by default).
pub const MIN_HEARD_WITHIN: Duration = Duration::from_secs(60);
/// Views examined per check: [`Liveness`] keeps the votes of its last 16.
const SCAN_VIEWS: u64 = 16;

/// `…` and the last 6 characters of an identifier, as logs name peers.
pub fn tail(id: &str) -> String {
    format!("…{}", &id[id.len().saturating_sub(6)..])
}

/// When each GLOBAL prover's consensus message last arrived, by its index
/// in the ordered committee. The inbound router records every message,
/// repeats included: consensus drops repeated votes before reporting them.
pub struct GlobalContact {
    /// The committee in participant order (sorted, as consensus orders it).
    members: Vec<FalconPublicKey>,
    heard: Mutex<Vec<Option<Instant>>>,
}

impl GlobalContact {
    pub fn new(members: impl IntoIterator<Item = FalconPublicKey>) -> Self {
        let mut members: Vec<FalconPublicKey> = members.into_iter().collect();
        members.sort();
        members.dedup();
        let heard = Mutex::new(vec![None; members.len()]);
        Self { members, heard }
    }

    /// A consensus message from `from` arrived.
    pub fn heard(&self, from: &FalconPublicKey) {
        self.heard_at(from, Instant::now());
    }

    fn heard_at(&self, from: &FalconPublicKey, now: Instant) {
        let Ok(index) = self.members.binary_search(from) else {
            return;
        };
        if let Ok(mut heard) = self.heard.lock() {
            heard[index] = Some(now);
        }
    }

    fn last_heard(&self) -> Vec<Option<Instant>> {
        self.heard
            .lock()
            .map(|heard| heard.clone())
            .unwrap_or_default()
    }
}

/// The GLOBAL provers this GLOBAL prover hears, as the node's GLOBAL
/// progress condition reports them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalReach {
    pub provers: usize,
    /// Heard from recently, this node included.
    pub reachable: usize,
    pub quorum: usize,
    /// The silent provers' labels, for this node's log only.
    pub unreachable: Vec<String>,
    /// How long the head may stay before it is a stall: four leader
    /// timeouts, and at least [`MIN_STALL_AFTER`].
    pub stall_after: Duration,
}

static REACH: Mutex<Option<(GlobalReach, Instant)>> = Mutex::new(None);

/// The GLOBAL provers this node heard at the watch's latest check; `None`
/// when it is not a GLOBAL prover, or the watch stopped.
pub fn reach() -> Option<GlobalReach> {
    let latest = REACH.lock().ok()?.clone();
    latest
        .filter(|(_, at)| at.elapsed() <= REACH_FRESH)
        .map(|(reach, _)| reach)
}

fn publish(reach: GlobalReach) {
    if let Ok(mut latest) = REACH.lock() {
        *latest = Some((reach, Instant::now()));
    }
}

/// `skipped` leader turns passed without a proposal since the previous
/// line, over `window_secs`, per leader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub skipped: u64,
    pub window_secs: u64,
    pub leaders: Vec<(String, u64)>,
    pub last_view: u64,
    pub last_leader: String,
}

/// The leader of `view`: consensus elects round-robin over the ordered
/// committee without a shuffle seed (`RoundRobin::<Sha256>::default()` in
/// `engine_host::build_global_engine`), index `(epoch + view) % n`
/// (`RoundRobinElector::elect`).
pub fn leader_of(epoch: u64, view: u64, members: usize) -> usize {
    (epoch.wrapping_add(view) as usize) % members.max(1)
}

/// The state behind [`GlobalReach`] and [`Skipped`]; the caller supplies
/// the clock, view and votes, so it runs without a consensus host.
pub struct GlobalWatch {
    /// Member labels in participant order.
    labels: Vec<String>,
    own: Option<usize>,
    quorum: usize,
    epoch: u64,
    stall_after: Duration,
    heard_within: Duration,
    /// The highest view examined for a skipped turn.
    checked: u64,
    skipped: BTreeMap<usize, u64>,
    skip_since: Option<Instant>,
    skip_logged: Option<Instant>,
    last_skip: Option<(u64, usize)>,
}

impl GlobalWatch {
    /// `quorum` as consensus computes it; `leader_timeout` and
    /// `timeout_retry` as the engine runs them.
    pub fn new(
        labels: Vec<String>,
        own: Option<usize>,
        quorum: usize,
        epoch: u64,
        leader_timeout: Duration,
        timeout_retry: Duration,
    ) -> Self {
        Self {
            labels,
            own,
            quorum,
            epoch,
            stall_after: (leader_timeout * 4).max(MIN_STALL_AFTER),
            heard_within: (timeout_retry * 4).max(MIN_HEARD_WITHIN),
            checked: 0,
            skipped: BTreeMap::new(),
            skip_since: None,
            skip_logged: None,
            last_skip: None,
        }
    }

    fn label(&self, member: usize) -> String {
        if Some(member) == self.own {
            return "this node".to_string();
        }
        self.labels
            .get(member)
            .cloned()
            .unwrap_or_else(|| format!("member {member}"))
    }

    /// Look at the highest consensus view `view` and the votes of recent
    /// views: the skipped leader turns to log, when a line is due.
    pub fn check(
        &mut self,
        now: Instant,
        view: u64,
        votes: impl Fn(u64) -> Option<ViewSigners>,
    ) -> Option<Skipped> {
        self.scan_skips(now, view, &votes);
        self.report_skips(now)
    }

    /// The GLOBAL provers heard within the heard window at `now`, given when
    /// each member was last heard.
    pub fn reach(&self, now: Instant, heard: &[Option<Instant>]) -> GlobalReach {
        let provers = self.labels.len();
        let reached = |member: usize| {
            Some(member) == self.own
                || heard
                    .get(member)
                    .copied()
                    .flatten()
                    .is_some_and(|at| now.saturating_duration_since(at) <= self.heard_within)
        };
        let unreachable: Vec<String> = (0..provers)
            .filter(|member| !reached(*member))
            .map(|member| self.label(member))
            .collect();
        GlobalReach {
            provers,
            reachable: provers - unreachable.len(),
            quorum: self.quorum,
            unreachable,
            stall_after: self.stall_after,
        }
    }

    /// Count the views before `view` that were nullified by a quorum without
    /// any notarize vote. The view before `view` is left for the next check,
    /// so its votes can arrive.
    fn scan_skips(&mut self, now: Instant, view: u64, votes: &impl Fn(u64) -> Option<ViewSigners>) {
        let last = view.saturating_sub(2);
        let first = (self.checked + 1)
            .max(last.saturating_sub(SCAN_VIEWS - 1))
            .max(1);
        if last < first {
            return;
        }
        for scanned in first..=last {
            let Some(signers) = votes(scanned) else {
                continue;
            };
            if !signers.notarize.is_empty() || signers.nullify.len() < self.quorum {
                continue;
            }
            let leader = leader_of(self.epoch, scanned, self.labels.len());
            *self.skipped.entry(leader).or_default() += 1;
            self.skip_since.get_or_insert(now);
            self.last_skip = Some((scanned, leader));
        }
        self.checked = last;
    }

    fn report_skips(&mut self, now: Instant) -> Option<Skipped> {
        let since = self.skip_since?;
        if self
            .skip_logged
            .is_some_and(|logged| now.saturating_duration_since(logged) < SKIP_REPORT_EVERY)
        {
            return None;
        }
        let (last_view, last_leader) = self.last_skip?;
        let skipped = std::mem::take(&mut self.skipped);
        self.skip_since = None;
        self.skip_logged = Some(now);
        Some(Skipped {
            skipped: skipped.values().sum(),
            window_secs: now.saturating_duration_since(since).as_secs(),
            leaders: skipped
                .into_iter()
                .map(|(leader, count)| (self.label(leader), count))
                .collect(),
            last_view,
            last_leader: self.label(last_leader),
        })
    }
}

/// Write `skipped` as one line.
pub fn emit(skipped: &Skipped) {
    let Skipped {
        skipped,
        window_secs,
        leaders,
        last_view,
        last_leader,
    } = skipped;
    let leaders = leaders
        .iter()
        .map(|(leader, count)| format!("{leader} ({count})"))
        .collect::<Vec<_>>()
        .join(", ");
    tracing::info!(skipped, window_secs, %leaders, last_view, %last_leader, scope = "network",
        "GLOBAL leader turns skipped: their views were nullified without a proposal, each costing a leader \
         timeout; a leader listed repeatedly is stopped, unreachable or cannot build a proposal");
}

/// Run the watch every [`CHECK_EVERY`] until `contact` is dropped,
/// publishing each check's [`reach`].
pub fn spawn(mut watch: GlobalWatch, contact: Weak<GlobalContact>, liveness: Arc<Liveness>) {
    tracing::info!(
        stall_after_secs = watch.stall_after.as_secs(),
        heard_within_secs = watch.heard_within.as_secs(),
        provers = watch.labels.len(),
        quorum = watch.quorum,
        "GLOBAL prover watch started"
    );
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CHECK_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let Some(contact) = contact.upgrade() else {
                break;
            };
            let (now, view) = (Instant::now(), liveness.snapshot().view);
            if let Some(skipped) = watch.check(now, view, |view| liveness.view_signers(view)) {
                emit(&skipped);
            }
            publish(watch.reach(now, &contact.last_heard()));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const LEADER: Duration = Duration::from_secs(30);
    const RETRY: Duration = Duration::from_secs(15);

    fn watch() -> GlobalWatch {
        let labels = ["…aaaaaa", "…bbbbbb", "…cccccc", "…dddddd"]
            .map(String::from)
            .to_vec();
        GlobalWatch::new(labels, Some(0), 3, 0, LEADER, RETRY)
    }

    /// Reach counts this node and the members heard within the heard
    /// window, names the silent ones and carries the stall window; the
    /// node's GLOBAL progress condition reads what was published.
    #[test]
    fn reach_counts_the_provers_heard_within_the_window() {
        let watch = watch();
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        // Member 1 is heard at 90 s, member 2 at 30 s, member 3 at start.
        let heard = vec![None, Some(at(90)), Some(at(30)), Some(start)];
        let reach = watch.reach(at(90), &heard);
        assert_eq!(
            reach,
            GlobalReach {
                provers: 4,
                reachable: 3,
                quorum: 3,
                unreachable: vec!["…dddddd".into()],
                stall_after: Duration::from_secs(120),
            }
        );
        // Member 2 falls silent too: 2 of 4, below quorum.
        let later = watch.reach(at(91), &heard);
        assert_eq!(
            (later.reachable, later.unreachable),
            (2, vec!["…cccccc".to_string(), "…dddddd".to_string()])
        );
        publish(reach.clone());
        assert_eq!(super::reach(), Some(reach));
    }

    #[test]
    fn longer_leader_timeouts_raise_the_threshold_and_the_heard_window() {
        let watch = GlobalWatch::new(
            vec![],
            None,
            1,
            0,
            Duration::from_secs(60),
            Duration::from_secs(30),
        );
        assert_eq!(
            (watch.stall_after, watch.heard_within),
            (Duration::from_secs(240), Duration::from_secs(120))
        );
    }

    #[test]
    fn the_contact_records_members_by_their_committee_index() {
        let key = |byte: u8| FalconPublicKey::from_bytes(&[byte; 897]).unwrap();
        let contact = GlobalContact::new([key(9), key(3), key(5)]);
        let now = Instant::now();
        contact.heard_at(&key(9), now);
        contact.heard_at(&key(7), now);
        assert_eq!(contact.last_heard(), vec![None, None, Some(now)]);
    }

    fn votes(skipped: &'static [u64]) -> impl Fn(u64) -> Option<ViewSigners> {
        move |view| {
            let mut signers = ViewSigners {
                view,
                ..Default::default()
            };
            if skipped.contains(&view) {
                signers.nullify = [1, 2, 3].into();
            } else {
                signers.notarize = [0, 1, 2, 3].into();
                signers.finalize = [0, 1, 2, 3].into();
            }
            Some(signers)
        }
    }

    #[test]
    fn skipped_leader_turns_are_logged_at_once_then_at_most_every_interval() {
        let mut watch = watch();
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        // Views 3 and 7 are led by member 3 (epoch 0, 4 members): nullified
        // by three members without a notarize vote.
        let skipped: &[u64] = &[3, 7, 11, 15, 19];
        let first = watch.check(at(0), 6, votes(skipped));
        assert_eq!(
            first,
            Some(Skipped {
                skipped: 1,
                window_secs: 0,
                leaders: vec![("…dddddd".into(), 1)],
                last_view: 3,
                last_leader: "…dddddd".into(),
            })
        );
        // View 7 waits until view 9 is under way; later turns aggregate.
        assert!(watch.check(at(10), 8, votes(skipped)).is_none());
        assert!(watch.check(at(20), 9, votes(skipped)).is_none());
        assert!(
            watch.check(at(599), 21, votes(skipped)).is_none(),
            "no line before the interval"
        );
        let second = watch.check(at(600), 22, votes(skipped));
        assert_eq!(
            second,
            Some(Skipped {
                skipped: 4,
                window_secs: 580,
                leaders: vec![("…dddddd".into(), 4)],
                last_view: 19,
                last_leader: "…dddddd".into(),
            })
        );
        assert!(
            watch.check(at(1300), 30, votes(skipped)).is_none(),
            "nothing new, nothing logged"
        );
    }

    #[test]
    fn a_view_with_a_proposal_or_without_a_nullify_quorum_is_not_a_skipped_turn() {
        let mut watch = watch();
        let now = Instant::now();
        let partial = |view: u64| {
            Some(ViewSigners {
                view,
                nullify: [1, 2].into(),
                ..Default::default()
            })
        };
        assert!(watch.check(now, 10, partial).is_none());
        let mut watch = super::tests::watch();
        let refused = |view: u64| {
            Some(ViewSigners {
                view,
                notarize: [3].into(),
                nullify: [0, 1, 2].into(),
                ..Default::default()
            })
        };
        assert!(watch.check(now, 10, refused).is_none());
    }

    #[test]
    fn a_long_gap_scans_only_the_views_liveness_keeps() {
        let mut watch = watch();
        let scanned = std::cell::RefCell::new(Vec::new());
        watch.check(Instant::now(), 1_000_000, |view| {
            scanned.borrow_mut().push(view);
            None
        });
        assert_eq!(
            scanned.into_inner(),
            (999_983..=999_998).collect::<Vec<_>>()
        );
    }

    #[test]
    fn leaders_rotate_round_robin_over_the_committee() {
        assert_eq!(
            (leader_of(0, 3, 4), leader_of(2, 3, 4), leader_of(0, 4, 4)),
            (3, 1, 0)
        );
    }
}
