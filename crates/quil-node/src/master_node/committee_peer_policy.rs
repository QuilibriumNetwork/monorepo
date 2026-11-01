//! IP-colocation exemptions come from committed session heads for shards this
//! node serves. Self-reported PeerInfo and transport subscriptions cannot grant
//! an exemption; all other peer-score terms remain active.

use std::collections::{BTreeSet, HashSet};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use quil_cw_consensus::handoff::Session;
use quil_p2p::PeerId;
use quil_types::error::{QuilError, Result};
use tracing::{info, warn};

pub(super) struct RefreshGuard(pub Arc<AtomicBool>);
impl Drop for RefreshGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub(super) fn collect(
    filters: &BTreeSet<Vec<u8>>,
    head: impl Fn(&[u8]) -> Result<Option<Session>>,
) -> Result<HashSet<PeerId>> {
    if filters.len() > 4096 {
        return Err(QuilError::P2p(
            "committee peer policy exceeds its shard bounds".into(),
        ));
    }
    let mut peers = HashSet::new();
    for filter in filters {
        let Some(session) = head(filter)? else {
            continue;
        };
        if session.filter != *filter {
            return Err(QuilError::P2p(
                "committee peer policy session filter mismatch".into(),
            ));
        }
        session.validate()?;
        for key in &session.members {
            let id = PeerId::from_bytes(&quil_p2p::peer_id_from_falcon_pubkey(key))
                .map_err(|_| QuilError::P2p("invalid committee network identity".into()))?;
            peers.insert(id);
            if peers.len() > 16_384 {
                return Err(QuilError::P2p(
                    "committee peer policy exceeds its peer bounds".into(),
                ));
            }
        }
    }
    Ok(peers)
}

/// How long a continuing unavailability stays quiet between reminders.
pub(super) const UNAVAILABLE_REPEAT: Duration = Duration::from_secs(600);

/// How long an expected wait ([`Cause::Bootstrap`], [`Cause::GlobalSync`])
/// logs at info before its reminders warn. A regular node first writes its
/// GLOBAL materialized cursor from its startup state jump (retried every
/// 3 s) or from a periodic prover tree reconcile (every 300 s by default);
/// 30 min covers the initial sync and six reconcile passes, so a wait past
/// it means both kept failing.
pub(super) const EXPECTED_WAIT_WARN_AFTER: Duration = Duration::from_secs(30 * 60);

/// What an operator does about an expected wait, at info and past its bound.
const EXPECTED_WAIT_ACTION: &str = "no action needed: this ends when this node \
    materializes its first GLOBAL frame from archive sync, and the line 'committee \
    membership readable again' follows; a missing port forward does not cause it; past \
    30 min it warns: then check that 'initial prover tree sync complete' was logged and \
    that no 'archive connection still failing' warning repeats";

/// What peers lose while the policy is unavailable.
const EFFECT: &str = "members of this node's committees that share an IP address \
    get no IP-colocation exemption from peer scoring until it ends";

/// Why the committed session heads cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Cause {
    /// No GLOBAL frame materialized locally yet: the normal state of a fresh
    /// start until the first one commits.
    Bootstrap,
    /// A GLOBAL state sync from an archive has installed some of its chunks
    /// but not the last: an expected wait that ends when it does.
    GlobalSync,
    /// Anything else: committed GLOBAL state this node cannot read or trust.
    Other,
}

impl Cause {
    fn of(error: &QuilError) -> Self {
        match error {
            // `CommittedView::capture` before the first materialized GLOBAL frame.
            QuilError::ExecutionUnavailable(message)
                if message.contains("no materialized cursor") =>
            {
                Self::Bootstrap
            }
            error if quil_execution::global_intrinsic::handoff::global_sync_in_progress(error) => {
                Self::GlobalSync
            }
            _ => Self::Other,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "global history not materialized yet",
            Self::GlobalSync => quil_execution::global_intrinsic::handoff::GLOBAL_SYNC_IN_PROGRESS,
            Self::Other => "committed global state unreadable",
        }
    }
}

/// What one refresh outcome did to the unavailability episode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Transition {
    /// A new episode began; `replaced` is the episode of another cause it ends.
    Started {
        cause: Cause,
        replaced: Option<(Cause, Duration, u64)>,
    },
    /// The episode continues inside its reminder interval: nothing logged.
    Suppressed,
    /// The episode continues and its reminder is due.
    Repeated {
        cause: Cause,
        duration: Duration,
        failures: u64,
    },
    /// The policy is readable again.
    Ended {
        cause: Cause,
        duration: Duration,
        failures: u64,
    },
}

struct Episode {
    cause: Cause,
    started: Instant,
    logged: Instant,
    failures: u64,
}

/// Turns the refresh's per-tick failures (every 5 s) into one line when an
/// unavailability starts, a reminder every [`UNAVAILABLE_REPEAT`] with its
/// duration and failure count, and one info line when it ends. An expected
/// wait logs at info until [`EXPECTED_WAIT_WARN_AFTER`] ([`Transition::warns`]).
#[derive(Default)]
pub(super) struct Unavailability(Option<Episode>);

impl Unavailability {
    pub(super) fn failed(&mut self, error: &QuilError, now: Instant) -> Transition {
        let cause = Cause::of(error);
        let transition = match self.0.as_mut().filter(|episode| episode.cause == cause) {
            Some(episode) => {
                episode.failures += 1;
                if now.saturating_duration_since(episode.logged) < UNAVAILABLE_REPEAT {
                    return Transition::Suppressed;
                }
                episode.logged = now;
                Transition::Repeated {
                    cause,
                    duration: now.saturating_duration_since(episode.started),
                    failures: episode.failures,
                }
            }
            None => {
                let replaced = self
                    .0
                    .replace(Episode {
                        cause,
                        started: now,
                        logged: now,
                        failures: 1,
                    })
                    .map(|old| {
                        (
                            old.cause,
                            now.saturating_duration_since(old.started),
                            old.failures,
                        )
                    });
                Transition::Started { cause, replaced }
            }
        };
        transition.log(Some(error));
        transition
    }

    pub(super) fn recovered(&mut self, now: Instant) -> Option<Transition> {
        let episode = self.0.take()?;
        let transition = Transition::Ended {
            cause: episode.cause,
            duration: now.saturating_duration_since(episode.started),
            failures: episode.failures,
        };
        transition.log(None);
        Some(transition)
    }
}

impl Transition {
    /// Whether the line warns: an unreadable state at once, an expected wait
    /// only once it lasts [`EXPECTED_WAIT_WARN_AFTER`].
    fn warns(&self) -> bool {
        match *self {
            Transition::Started { cause, .. } => cause == Cause::Other,
            Transition::Repeated {
                cause, duration, ..
            } => cause == Cause::Other || duration >= EXPECTED_WAIT_WARN_AFTER,
            Transition::Suppressed | Transition::Ended { .. } => false,
        }
    }

    fn log(&self, error: Option<&QuilError>) {
        let error = error.map_or_else(String::new, ToString::to_string);
        let repeat_every_s = UNAVAILABLE_REPEAT.as_secs();
        let warn_after_s = EXPECTED_WAIT_WARN_AFTER.as_secs();
        match *self {
            Transition::Started { cause, replaced } => {
                let replaced = replaced.map_or_else(
                    || "none".to_string(),
                    |(old, duration, failures)| {
                        format!(
                            "{} after {}s and {} failures",
                            old.as_str(),
                            duration.as_secs(),
                            failures
                        )
                    },
                );
                match cause {
                    Cause::Bootstrap => info!(
                        scope = "this node",
                        cause = cause.as_str(),
                        %error,
                        replaced = %replaced,
                        repeat_every_s,
                        warn_after_s,
                        effect = EFFECT,
                        action = EXPECTED_WAIT_ACTION,
                        "waiting for the first synced GLOBAL state after start; nothing to fix yet"
                    ),
                    Cause::GlobalSync => info!(
                        scope = "this node",
                        cause = cause.as_str(),
                        replaced = %replaced,
                        repeat_every_s,
                        warn_after_s,
                        effect = EFFECT,
                        action = "no action needed: this ends when the GLOBAL state sync from an archive installs its last chunk, or when a later prover tree sync completes if this one fails; past 30 min it warns: then check that no 'archive connection still failing' warning repeats",
                        "waiting for a GLOBAL state sync from an archive to finish; nothing to fix yet"
                    ),
                    Cause::Other => warn!(
                        scope = "this node",
                        cause = cause.as_str(),
                        %error,
                        replaced = %replaced,
                        repeat_every_s,
                        effect = EFFECT,
                        action = "if the 10-min reminder shows it continues, report the error text to the maintainer",
                        "this node cannot read the committee membership in its committed GLOBAL state"
                    ),
                }
            }
            Transition::Suppressed => {}
            Transition::Repeated {
                cause,
                duration,
                failures,
            } => {
                let duration_s = duration.as_secs();
                if cause == Cause::Other {
                    warn!(
                        scope = "this node",
                        cause = cause.as_str(),
                        %error,
                        duration_s,
                        failures,
                        effect = EFFECT,
                        action = "report the error text to the maintainer",
                        "this node still cannot read the committee membership in its committed GLOBAL state"
                    );
                } else if self.warns() {
                    warn!(
                        scope = "this node",
                        cause = cause.as_str(),
                        %error,
                        duration_s,
                        failures,
                        warn_after_s,
                        effect = EFFECT,
                        action = "check that 'initial prover tree sync complete' was logged and that no 'archive connection still failing' warning repeats; if both look fine, report this line to the maintainer",
                        "the first synced GLOBAL state is overdue: this node has waited past its bound"
                    );
                } else {
                    info!(
                        scope = "this node",
                        cause = cause.as_str(),
                        %error,
                        duration_s,
                        failures,
                        warn_after_s,
                        action = EXPECTED_WAIT_ACTION,
                        "still waiting for synced GLOBAL state; nothing to fix yet"
                    );
                }
            }
            Transition::Ended {
                cause,
                duration,
                failures,
            } => info!(
                scope = "this node",
                cause = cause.as_str(),
                duration_s = duration.as_secs(),
                failures,
                "committee membership readable again; committee peers get their IP-colocation exemption"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::crypto::Signer;

    fn session(filter: Vec<u8>, signer: &quil_crypto::FalconSigner) -> Session {
        Session {
            chain_id: [0; 32],
            filter,
            generation: 1,
            genesis: [0; 32],
            base_frame: 0,
            authorization: [0; 32],
            members: vec![signer.public_key().to_vec()],
        }
    }

    #[test]
    fn selection_tracks_served_committed_heads_and_removes_departed_members() {
        let a = quil_crypto::FalconSigner::generate();
        let b = quil_crypto::FalconSigner::generate();
        let fa = vec![1; 32];
        let fb = vec![2; 32];
        let sa = session(fa.clone(), &a);
        let sb = session(fb.clone(), &b);
        let pa = PeerId::from_bytes(&quil_p2p::peer_id_from_falcon_pubkey(a.public_key())).unwrap();
        let pb = PeerId::from_bytes(&quil_p2p::peer_id_from_falcon_pubkey(b.public_key())).unwrap();
        let lookup = |filter: &[u8]| {
            Ok(if filter == fa {
                Some(sa.clone())
            } else {
                Some(sb.clone())
            })
        };
        assert_eq!(
            collect(&[fa.clone(), fb].into_iter().collect(), lookup).unwrap(),
            [pa, pb].into_iter().collect()
        );
        assert_eq!(
            collect(&[fa.clone()].into_iter().collect(), lookup).unwrap(),
            [pa].into_iter().collect()
        );
        assert!(collect(&[fa].into_iter().collect(), |_| Ok(None))
            .unwrap()
            .is_empty());
        assert!(
            collect(&BTreeSet::new(), |_| panic!("no unserved head lookup"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn corrupt_or_unavailable_head_cannot_grant_an_exemption() {
        let a = quil_crypto::FalconSigner::generate();
        let filter = vec![1; 32];
        let filters = [filter.clone()].into_iter().collect();
        let wrong = session(vec![2; 32], &a);
        assert!(collect(&filters, |_| Ok(Some(wrong.clone()))).is_err());
        let mut invalid = session(filter, &a);
        invalid.members = vec![vec![1]];
        assert!(collect(&filters, |_| Ok(Some(invalid.clone()))).is_err());
        assert!(collect(&filters, |_| Err(QuilError::Store("read failure".into()))).is_err());
    }

    fn bootstrap() -> QuilError {
        QuilError::ExecutionUnavailable("global handoff snapshot has no materialized cursor".into())
    }

    #[test]
    fn a_continuing_unavailability_warns_once_then_at_the_reminder_interval() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut state = Unavailability::default();
        assert_eq!(
            state.failed(&bootstrap(), t0),
            Transition::Started {
                cause: Cause::Bootstrap,
                replaced: None
            }
        );
        for s in (5..600).step_by(5) {
            assert_eq!(
                state.failed(&bootstrap(), at(s)),
                Transition::Suppressed,
                "tick at {s}s"
            );
        }
        assert_eq!(
            state.failed(&bootstrap(), at(600)),
            Transition::Repeated {
                cause: Cause::Bootstrap,
                duration: Duration::from_secs(600),
                failures: 121
            }
        );
        assert_eq!(state.failed(&bootstrap(), at(605)), Transition::Suppressed);
        assert_eq!(
            state.failed(&bootstrap(), at(1200)),
            Transition::Repeated {
                cause: Cause::Bootstrap,
                duration: Duration::from_secs(1200),
                failures: 123
            }
        );
    }

    #[test]
    fn recovery_ends_the_episode_once_and_a_later_failure_starts_another() {
        let t0 = Instant::now();
        let mut state = Unavailability::default();
        assert_eq!(state.recovered(t0), None);
        state.failed(&bootstrap(), t0);
        state.failed(&bootstrap(), t0 + Duration::from_secs(5));
        assert_eq!(
            state.recovered(t0 + Duration::from_secs(9)),
            Some(Transition::Ended {
                cause: Cause::Bootstrap,
                duration: Duration::from_secs(9),
                failures: 2
            })
        );
        assert_eq!(state.recovered(t0 + Duration::from_secs(10)), None);
        assert_eq!(
            state.failed(&bootstrap(), t0 + Duration::from_secs(15)),
            Transition::Started {
                cause: Cause::Bootstrap,
                replaced: None
            }
        );
    }

    /// A view withheld while a GLOBAL state sync installs its chunks is its
    /// own expected wait, not unreadable state to report.
    #[test]
    fn a_global_sync_in_progress_is_an_expected_wait_of_its_own() {
        use quil_execution::global_intrinsic::handoff::GLOBAL_SYNC_IN_PROGRESS;
        let t0 = Instant::now();
        let sync = QuilError::ExecutionUnavailable(GLOBAL_SYNC_IN_PROGRESS.into());
        assert_eq!(Cause::of(&sync), Cause::GlobalSync);
        let mut state = Unavailability::default();
        assert_eq!(
            state.failed(&bootstrap(), t0),
            Transition::Started {
                cause: Cause::Bootstrap,
                replaced: None
            }
        );
        assert_eq!(
            state.failed(&sync, t0 + Duration::from_secs(5)),
            Transition::Started {
                cause: Cause::GlobalSync,
                replaced: Some((Cause::Bootstrap, Duration::from_secs(5), 1))
            }
        );
        assert_eq!(
            state.failed(&sync, t0 + Duration::from_secs(10)),
            Transition::Suppressed
        );
        assert_eq!(
            state.recovered(t0 + Duration::from_secs(40)),
            Some(Transition::Ended {
                cause: Cause::GlobalSync,
                duration: Duration::from_secs(35),
                failures: 2
            })
        );
    }

    #[test]
    fn only_the_missing_cursor_counts_as_the_bootstrap_wait_and_a_cause_change_warns() {
        let t0 = Instant::now();
        let other = QuilError::Store("read failure".into());
        let coverage =
            QuilError::ExecutionUnavailable("operation requires complete domain coverage".into());
        assert_eq!(Cause::of(&bootstrap()), Cause::Bootstrap);
        assert_eq!(Cause::of(&other), Cause::Other);
        assert_eq!(Cause::of(&coverage), Cause::Other);
        let mut state = Unavailability::default();
        state.failed(&bootstrap(), t0);
        assert_eq!(
            state.failed(&other, t0 + Duration::from_secs(5)),
            Transition::Started {
                cause: Cause::Other,
                replaced: Some((Cause::Bootstrap, Duration::from_secs(5), 1))
            }
        );
        // Other causes with different text share one episode.
        assert_eq!(
            state.failed(&coverage, t0 + Duration::from_secs(10)),
            Transition::Suppressed
        );
        assert_eq!(
            state.failed(&bootstrap(), t0 + Duration::from_secs(15)),
            Transition::Started {
                cause: Cause::Bootstrap,
                replaced: Some((Cause::Other, Duration::from_secs(10), 2))
            }
        );
    }

    /// A fresh start's wait for its first synced GLOBAL state logs at info
    /// (an operator read the old warning as a port-forward problem) and
    /// warns only once it lasts [`EXPECTED_WAIT_WARN_AFTER`]; an unreadable
    /// state warns at once.
    #[test]
    fn an_expected_wait_logs_at_info_until_its_bound_then_warns() {
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut state = Unavailability::default();
        assert!(!state.failed(&bootstrap(), t0).warns(), "a fresh start");
        let mut reminders = Vec::new();
        for s in (5..=1800).step_by(5) {
            let transition = state.failed(&bootstrap(), at(s));
            if transition != Transition::Suppressed {
                reminders.push((s, transition.warns()));
            }
        }
        assert_eq!(
            reminders,
            vec![(600, false), (1200, false), (1800, true)],
            "reminders inside the bound stay at info"
        );
        let sync = QuilError::ExecutionUnavailable(
            quil_execution::global_intrinsic::handoff::GLOBAL_SYNC_IN_PROGRESS.into(),
        );
        let mut syncing = Unavailability::default();
        assert!(!syncing.failed(&sync, t0).warns());
        assert!(!syncing.failed(&sync, at(600)).warns());
        assert!(syncing.failed(&sync, at(1800)).warns());
        let mut other = Unavailability::default();
        let unreadable = QuilError::Store("read failure".into());
        assert!(other.failed(&unreadable, t0).warns());
        assert!(other.failed(&unreadable, at(600)).warns());
        assert!(!other.recovered(at(605)).unwrap().warns());
    }
}
