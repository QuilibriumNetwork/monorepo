//! Operator signals for GLOBAL consensus on a GLOBAL prover: a warning while
//! the GLOBAL head stops advancing, and a bounded count of the leader turns
//! that pass without a proposal.
//!
//! A halted GLOBAL committee logs little on its live members: transport
//! warnings about the missing members and routine status lines. Nothing said
//! that GLOBAL had stopped, for how long, or that it lacks the members its
//! quorum needs. [`GlobalWatch`] says so: one warning once the head has not
//! advanced for [`GlobalWatch::stall_after`], a repeat every [`STALL_REPEAT`]
//! with its duration, and one line when the head advances again. Each warning
//! counts the GLOBAL provers heard from recently against the quorum
//! consensus needs and names the silent ones.
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
use quil_types::store::ClockStore;

/// How often the watch looks at the GLOBAL head.
pub const CHECK_EVERY: Duration = Duration::from_secs(10);
/// The shortest stall that warns. A frame takes about 10 s
/// ([`crate::difficulty::IDEAL_FRAME_TIME`]); a leader turn without a
/// proposal adds a leader timeout (30 s by default). The threshold is four
/// leader timeouts and at least this, so three consecutive skipped turns and
/// a frame do not warn.
pub const MIN_STALL_AFTER: Duration = Duration::from_secs(120);
/// How often a continuing stall warns again.
pub const STALL_REPEAT: Duration = Duration::from_secs(300);
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

/// What the watch logs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GlobalLog {
    /// The head has not advanced for `stalled_secs`.
    Stalled {
        frame: u64,
        stalled_secs: u64,
        view: u64,
        provers: usize,
        reachable: usize,
        quorum: usize,
        unreachable: Vec<String>,
        repeat: bool,
    },
    /// The head advanced after a warned stall of `stalled_secs`.
    Resumed { frame: u64, stalled_secs: u64 },
    /// `skipped` leader turns passed without a proposal since the previous
    /// line, over `window_secs`, per leader.
    Skipped {
        skipped: u64,
        window_secs: u64,
        leaders: Vec<(String, u64)>,
        last_view: u64,
        last_leader: String,
    },
}

/// The leader of `view`: consensus elects round-robin over the ordered
/// committee without a shuffle seed (`RoundRobin::<Sha256>::default()` in
/// `engine_host::build_global_engine`), index `(epoch + view) % n`
/// (`RoundRobinElector::elect`).
pub fn leader_of(epoch: u64, view: u64, members: usize) -> usize {
    (epoch.wrapping_add(view) as usize) % members.max(1)
}

/// The state behind [`GlobalLog`]; the caller supplies the clock, head,
/// view and votes, so it runs without a consensus host.
pub struct GlobalWatch {
    /// Member labels in participant order.
    labels: Vec<String>,
    own: Option<usize>,
    quorum: usize,
    epoch: u64,
    stall_after: Duration,
    heard_within: Duration,
    head: Option<u64>,
    advanced: Option<Instant>,
    warned: Option<Instant>,
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
            head: None,
            advanced: None,
            warned: None,
            checked: 0,
            skipped: BTreeMap::new(),
            skip_since: None,
            skip_logged: None,
            last_skip: None,
        }
    }

    pub fn stall_after(&self) -> Duration {
        self.stall_after
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

    /// Look at the head `head`, the highest consensus view `view`, when each
    /// member was last heard, and the votes of recent views.
    pub fn check(
        &mut self,
        now: Instant,
        head: u64,
        view: u64,
        heard: &[Option<Instant>],
        votes: impl Fn(u64) -> Option<ViewSigners>,
    ) -> Vec<GlobalLog> {
        let mut logs = Vec::new();
        self.scan_skips(now, view, &votes);
        if let Some(log) = self.report_skips(now) {
            logs.push(log);
        }
        if let Some(log) = self.check_head(now, head, view, heard) {
            logs.push(log);
        }
        logs
    }

    fn check_head(
        &mut self,
        now: Instant,
        head: u64,
        view: u64,
        heard: &[Option<Instant>],
    ) -> Option<GlobalLog> {
        let since = match (self.head, self.advanced) {
            (Some(previous), Some(since)) if previous == head => since,
            _ => {
                let stalled = self
                    .advanced
                    .map(|since| now.saturating_duration_since(since));
                self.head = Some(head);
                self.advanced = Some(now);
                return self.warned.take().map(|_| GlobalLog::Resumed {
                    frame: head,
                    stalled_secs: stalled.unwrap_or_default().as_secs(),
                });
            }
        };
        let stalled = now.saturating_duration_since(since);
        if stalled < self.stall_after {
            return None;
        }
        if self
            .warned
            .is_some_and(|warned| now.saturating_duration_since(warned) < STALL_REPEAT)
        {
            return None;
        }
        let repeat = self.warned.replace(now).is_some();
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
        Some(GlobalLog::Stalled {
            frame: head,
            stalled_secs: stalled.as_secs(),
            view,
            provers,
            reachable: provers - unreachable.len(),
            quorum: self.quorum,
            unreachable,
            repeat,
        })
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

    fn report_skips(&mut self, now: Instant) -> Option<GlobalLog> {
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
        Some(GlobalLog::Skipped {
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

/// Write `log` as one line.
pub fn emit(log: &GlobalLog) {
    match log {
        GlobalLog::Stalled {
            frame,
            stalled_secs,
            view,
            provers,
            reachable,
            quorum,
            unreachable,
            repeat,
        } => {
            let unreachable = unreachable.join(", ");
            if reachable < quorum {
                tracing::warn!(frame, stalled_secs, view, provers, reachable, quorum, %unreachable, repeat,
                    scope = "network", action = "check",
                    "GLOBAL halted network-wide: {reachable} of {provers} GLOBAL provers reachable, {quorum} needed; \
                     it resumes when a missing prover returns, so bring the unreachable provers back");
            } else {
                tracing::warn!(frame, stalled_secs, view, provers, reachable, quorum, %unreachable, repeat,
                    scope = "network", action = "check",
                    "GLOBAL head not advancing although {reachable} of {provers} GLOBAL provers are reachable \
                     ({quorum} needed): compare the GLOBAL head and the proposal and verify warnings on the reachable provers");
            }
        }
        GlobalLog::Resumed {
            frame,
            stalled_secs,
        } => {
            tracing::info!(
                frame,
                stalled_secs,
                "GLOBAL advancing again after {stalled_secs}s"
            );
        }
        GlobalLog::Skipped {
            skipped,
            window_secs,
            leaders,
            last_view,
            last_leader,
        } => {
            let leaders = leaders
                .iter()
                .map(|(leader, count)| format!("{leader} ({count})"))
                .collect::<Vec<_>>()
                .join(", ");
            tracing::info!(skipped, window_secs, %leaders, last_view, %last_leader, scope = "network",
                "GLOBAL leader turns skipped: their views were nullified without a proposal, each costing a leader \
                 timeout; a leader listed repeatedly is stopped, unreachable or cannot build a proposal");
        }
    }
}

/// Run the watch every [`CHECK_EVERY`] until `contact` is dropped.
pub fn spawn(
    mut watch: GlobalWatch,
    contact: Weak<GlobalContact>,
    liveness: Arc<Liveness>,
    clock_store: Arc<dyn ClockStore>,
) {
    tracing::info!(
        stall_after_secs = watch.stall_after.as_secs(),
        heard_within_secs = watch.heard_within.as_secs(),
        provers = watch.labels.len(),
        quorum = watch.quorum,
        "GLOBAL stall watch started"
    );
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(CHECK_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let Some(contact) = contact.upgrade() else {
                break;
            };
            let Some(head) = clock_store
                .get_latest_global_clock_frame()
                .ok()
                .and_then(|frame| frame.header.map(|header| header.frame_number))
            else {
                continue;
            };
            let view = liveness.snapshot().view;
            for log in watch.check(Instant::now(), head, view, &contact.last_heard(), |view| {
                liveness.view_signers(view)
            }) {
                emit(&log);
            }
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

    fn none(_: u64) -> Option<ViewSigners> {
        None
    }

    #[test]
    fn a_stall_warns_at_its_threshold_repeats_after_the_interval_and_ends_when_the_head_advances() {
        let mut watch = watch();
        assert_eq!(watch.stall_after(), Duration::from_secs(120));
        let start = Instant::now();
        let at = |secs: u64| start + Duration::from_secs(secs);
        // Members 1 and 2 are heard; member 3 was last heard at start.
        let heard = |now: Instant| vec![None, Some(now), Some(now), Some(start)];
        assert!(watch
            .check(at(0), 935_134, 50, &heard(at(0)), none)
            .is_empty());
        for secs in [10, 60, 119] {
            assert!(
                watch
                    .check(at(secs), 935_134, 50, &heard(at(secs)), none)
                    .is_empty(),
                "no warning before 120 s ({secs})"
            );
        }
        let first = watch.check(at(120), 935_134, 50, &heard(at(120)), none);
        assert_eq!(
            first,
            vec![GlobalLog::Stalled {
                frame: 935_134,
                stalled_secs: 120,
                view: 50,
                provers: 4,
                reachable: 3,
                quorum: 3,
                unreachable: vec!["…dddddd".into()],
                repeat: false,
            }]
        );
        for secs in [130, 300, 419] {
            assert!(
                watch
                    .check(at(secs), 935_134, 50, &heard(at(secs)), none)
                    .is_empty(),
                "no repeat before 300 s ({secs})"
            );
        }
        // Member 2 falls silent too: the repeat counts 2 of 4 below quorum.
        let silent = vec![None, Some(at(420)), Some(at(300)), Some(start)];
        let repeat = watch.check(at(420), 935_134, 50, &silent, none);
        assert_eq!(
            repeat,
            vec![GlobalLog::Stalled {
                frame: 935_134,
                stalled_secs: 420,
                view: 50,
                provers: 4,
                reachable: 2,
                quorum: 3,
                unreachable: vec!["…cccccc".into(), "…dddddd".into()],
                repeat: true,
            }]
        );
        let resumed = watch.check(at(500), 935_135, 51, &heard(at(500)), none);
        assert_eq!(
            resumed,
            vec![GlobalLog::Resumed {
                frame: 935_135,
                stalled_secs: 500
            }]
        );
        assert!(
            watch
                .check(at(510), 935_136, 52, &heard(at(510)), none)
                .is_empty(),
            "an unwarned advance is quiet"
        );
        assert!(
            watch
                .check(at(629), 935_136, 52, &heard(at(629)), none)
                .is_empty(),
            "a new stall restarts the threshold"
        );
        assert!(matches!(
            watch.check(at(630), 935_136, 52, &heard(at(630)), none)[..],
            [GlobalLog::Stalled {
                stalled_secs: 120,
                repeat: false,
                ..
            }]
        ));
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
        let heard = vec![None; 4];
        // Views 3 and 7 are led by member 3 (epoch 0, 4 members): nullified
        // by three members without a notarize vote.
        let skipped: &[u64] = &[3, 7, 11, 15, 19];
        let first = watch.check(at(0), 10, 6, &heard, votes(skipped));
        assert_eq!(
            first,
            vec![GlobalLog::Skipped {
                skipped: 1,
                window_secs: 0,
                leaders: vec![("…dddddd".into(), 1)],
                last_view: 3,
                last_leader: "…dddddd".into(),
            }]
        );
        // View 7 waits until view 9 is under way; later turns aggregate.
        assert!(watch
            .check(at(10), 11, 8, &heard, votes(skipped))
            .is_empty());
        assert!(watch
            .check(at(20), 12, 9, &heard, votes(skipped))
            .is_empty());
        assert!(
            watch
                .check(at(599), 20, 21, &heard, votes(skipped))
                .is_empty(),
            "no line before the interval"
        );
        let second = watch.check(at(600), 21, 22, &heard, votes(skipped));
        assert_eq!(
            second,
            vec![GlobalLog::Skipped {
                skipped: 4,
                window_secs: 580,
                leaders: vec![("…dddddd".into(), 4)],
                last_view: 19,
                last_leader: "…dddddd".into(),
            }]
        );
        assert!(
            watch
                .check(at(1300), 30, 30, &heard, votes(skipped))
                .is_empty(),
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
        assert!(watch.check(now, 1, 10, &[], partial).is_empty());
        let mut watch = super::tests::watch();
        let refused = |view: u64| {
            Some(ViewSigners {
                view,
                notarize: [3].into(),
                nullify: [0, 1, 2].into(),
                ..Default::default()
            })
        };
        assert!(watch.check(now, 1, 10, &[], refused).is_empty());
    }

    #[test]
    fn a_long_gap_scans_only_the_views_liveness_keeps() {
        let mut watch = watch();
        let scanned = std::cell::RefCell::new(Vec::new());
        watch.check(Instant::now(), 1, 1_000_000, &[], |view| {
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
