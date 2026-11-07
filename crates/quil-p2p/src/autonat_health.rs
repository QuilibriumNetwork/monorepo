//! Operator logging of AutoNAT, this node's reachability check.
//!
//! AutoNAT logs each probe at debug level only, and a probe that fails
//! before any dial-back leaves its status unchanged, so a node whose probes
//! all fail stays unconfirmed without a trace at info level.
//! [`AutonatHealth`] classifies each probe outcome, follows the current run
//! of probes without a dial-back, and turns status changes and such runs
//! into bounded notices: a line when a run reaches [`FAILING_AFTER`] probes,
//! at most one per [`FAILING_REPEAT`] while it lasts, and one when a probe
//! succeeds again; status changes at most once per [`STATUS_LINE_EVERY`].
//! It also summarizes the run for the PeerInfo publisher's warning.

use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use libp2p::autonat::{NatStatus, OutboundFailure, OutboundProbeError, ResponseError};
use tracing::{info, warn};

use crate::external_addr::{AutonatSummary, ProbeFailureSummary};

/// Probes without a dial-back before the first line. AutoNAT retries every
/// 90 s (at once after a failed request), so this is a few minutes at most.
pub(crate) const FAILING_AFTER: u32 = 3;

/// Least interval between the lines of one run.
pub(crate) const FAILING_REPEAT: Duration = Duration::from_secs(10 * 60);

/// Least interval between status-change lines; flips in between are counted
/// in the next line.
pub(crate) const STATUS_LINE_EVERY: Duration = Duration::from_secs(10 * 60);

/// Servers on this many distinct IPs must have failed to dial us back, or
/// not within AutoNAT's timeout, before a run counts as this node being
/// unreachable. A NAT that drops dial-backs silently yields timeouts: a
/// server dials without a connect timeout, so our request times out first.
const UNREACHABLE_AFTER_IPS: usize = 2;

/// Why a probe produced no dial-back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProbeFailure {
    /// No server to ask: none registered, or all were used in the last
    /// 90 s. No request is sent.
    NoServer,
    /// This node has no listen address to offer. No request is sent.
    NoAddresses,
    /// The request got no response within AutoNAT's timeout.
    Timeout,
    /// The server does not serve AutoNAT.
    UnsupportedProtocol,
    /// The connection to the server closed before its response.
    ConnectionClosed,
    /// The server could not be dialed.
    DialFailure,
    /// The request stream failed (for example a request the server could
    /// not read).
    Io,
    /// The server refused to dial back (its rate limits, or it sees this
    /// node at a non-public address).
    DialRefused,
    /// The server dialed back and reached none of our addresses.
    DialError,
    /// The server could not use our request.
    BadRequest,
    /// The server failed internally.
    Internal,
}

const CLASS_COUNT: usize = 11;

const CLASSES: [ProbeFailure; CLASS_COUNT] = [
    ProbeFailure::NoServer,
    ProbeFailure::NoAddresses,
    ProbeFailure::Timeout,
    ProbeFailure::UnsupportedProtocol,
    ProbeFailure::ConnectionClosed,
    ProbeFailure::DialFailure,
    ProbeFailure::Io,
    ProbeFailure::DialRefused,
    ProbeFailure::DialError,
    ProbeFailure::BadRequest,
    ProbeFailure::Internal,
];

impl ProbeFailure {
    pub(crate) fn of(error: &OutboundProbeError) -> Self {
        match error {
            OutboundProbeError::NoServer => ProbeFailure::NoServer,
            OutboundProbeError::NoAddresses => ProbeFailure::NoAddresses,
            OutboundProbeError::OutboundRequest(failure) => match failure {
                OutboundFailure::DialFailure => ProbeFailure::DialFailure,
                OutboundFailure::Timeout => ProbeFailure::Timeout,
                OutboundFailure::ConnectionClosed => ProbeFailure::ConnectionClosed,
                OutboundFailure::UnsupportedProtocols => ProbeFailure::UnsupportedProtocol,
                OutboundFailure::Io(_) => ProbeFailure::Io,
            },
            OutboundProbeError::Response(error) => match error {
                ResponseError::DialError => ProbeFailure::DialError,
                ResponseError::DialRefused => ProbeFailure::DialRefused,
                ResponseError::BadRequest => ProbeFailure::BadRequest,
                ResponseError::InternalError => ProbeFailure::Internal,
            },
        }
    }

    /// Whether a request went to a server (`no_server` and `no_addresses`
    /// abort before one).
    fn sent(self) -> bool {
        !matches!(self, ProbeFailure::NoServer | ProbeFailure::NoAddresses)
    }

    /// A failure that may mean this node is unreachable.
    fn unreachable_class(self) -> bool {
        matches!(self, ProbeFailure::DialError | ProbeFailure::Timeout)
    }

    /// What the failure tells the address tracker.
    pub(crate) fn miss(self) -> crate::external_addr::ProbeMiss {
        if self.unreachable_class() {
            crate::external_addr::ProbeMiss::Unreachable
        } else {
            crate::external_addr::ProbeMiss::Inconclusive
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            ProbeFailure::NoServer => "no_server",
            ProbeFailure::NoAddresses => "no_addresses",
            ProbeFailure::Timeout => "timeout",
            ProbeFailure::UnsupportedProtocol => "unsupported_protocol",
            ProbeFailure::ConnectionClosed => "connection_closed",
            ProbeFailure::DialFailure => "dial_failure",
            ProbeFailure::Io => "io",
            ProbeFailure::DialRefused => "dial_refused",
            ProbeFailure::DialError => "dial_error",
            ProbeFailure::BadRequest => "bad_request",
            ProbeFailure::Internal => "internal",
        }
    }
}

/// Probe failures by class.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct FailureCounts([u32; CLASS_COUNT]);

impl FailureCounts {
    fn add(&mut self, failure: ProbeFailure) {
        self.0[failure as usize] += 1;
    }

    fn get(&self, failure: ProbeFailure) -> u32 {
        self.0[failure as usize]
    }

    /// The most frequent class; `last` wins a tie.
    fn dominant(&self, last: ProbeFailure) -> ProbeFailure {
        CLASSES.into_iter().fold(last, |best, c| {
            if self.get(c) > self.get(best) {
                c
            } else {
                best
            }
        })
    }
}

/// `timeout=4 io=1`, most frequent first; `none` when empty.
impl fmt::Display for FailureCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut counted: Vec<ProbeFailure> =
            CLASSES.into_iter().filter(|c| self.get(*c) > 0).collect();
        if counted.is_empty() {
            return f.write_str("none");
        }
        counted.sort_by_key(|c| std::cmp::Reverse(self.get(*c)));
        for (i, c) in counted.into_iter().enumerate() {
            let sep = if i == 0 { "" } else { " " };
            write!(f, "{sep}{}={}", c.as_str(), self.get(c))?;
        }
        Ok(())
    }
}

/// A line for the operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AutonatNotice {
    /// AutoNAT's status of this node changed since the previous such line.
    StatusChanged {
        /// The status of the previous line (`unknown` at start).
        old: &'static str,
        new: &'static str,
        /// Time since the previous line, or since start.
        previous_secs: u64,
        /// Probes finished since the previous line.
        probes: u32,
        failures: FailureCounts,
        /// Flips in between, not logged on their own.
        suppressed_flips: u32,
    },
    /// `probes` probes in a row brought no dial-back: the first line of the
    /// run, or a repeat.
    Failing {
        repeat: bool,
        probes: u32,
        /// Attempts aborted before a request (`no_server`, `no_addresses`).
        aborted: u32,
        secs: u64,
        failures: FailureCounts,
        dominant: ProbeFailure,
        last: ProbeFailure,
        /// Distinct remote IPs of the run's servers.
        server_ips: usize,
        hint: &'static str,
    },
    /// A probe brought a dial-back after a reported run.
    Recovered {
        probes: u32,
        secs: u64,
        failures: FailureCounts,
    },
}

/// The current run of probes without a dial-back.
struct Run {
    started: Instant,
    /// Requests sent to a server.
    probes: u32,
    /// Attempts aborted before a request.
    aborted: u32,
    failures: FailureCounts,
    last: ProbeFailure,
    server_ips: HashSet<IpAddr>,
    /// Servers whose dial-back failed or did not finish.
    unreachable_ips: HashSet<IpAddr>,
    /// When its latest line was logged; `None` before the first.
    last_line: Option<Instant>,
    /// A failure other than `dial_error` or `timeout` since that line.
    inconclusive_since_line: bool,
}

impl Run {
    fn unreachable(&self) -> bool {
        self.unreachable_ips.len() >= UNREACHABLE_AFTER_IPS
    }

    fn hint(&self) -> &'static str {
        match self.failures.dominant(self.last) {
            // With servers registered, `log` says they were all used
            // recently instead (see `hint_for`).
            ProbeFailure::NoServer => {
                "no connected peer serves AutoNAT; check this node's peer connections"
            }
            ProbeFailure::NoAddresses => {
                "this node has no listen address to offer; check p2p.listenMultiaddr"
            }
            ProbeFailure::DialError if self.unreachable() => {
                "servers on distinct IPs could not dial this node back; check the port forward of \
                 the p2p port"
            }
            ProbeFailure::DialError => {
                "a server could not dial this node back; waiting for servers on other IPs"
            }
            ProbeFailure::DialRefused => {
                "servers declined to dial back, usually at their own connection or rate limits; \
                 expected now and then, no action needed"
            }
            ProbeFailure::DialFailure => {
                "the chosen servers could not be dialed; check this node's outbound connectivity \
                 if it persists"
            }
            ProbeFailure::Timeout => {
                "dial-backs did not finish within 30 s; check the port forward of the p2p port \
                 first, report if it is forwarded"
            }
            ProbeFailure::ConnectionClosed => {
                "connections to the servers closed before their answer; report this line if it \
                 persists"
            }
            ProbeFailure::UnsupportedProtocol
            | ProbeFailure::Io
            | ProbeFailure::BadRequest
            | ProbeFailure::Internal => {
                "requests fail before any dial-back result, so reachability is unknown and a port \
                 forward does not help; report this line"
            }
        }
    }

    fn notice(&mut self, now: Instant, repeat: bool) -> AutonatNotice {
        self.last_line = Some(now);
        self.inconclusive_since_line = false;
        AutonatNotice::Failing {
            repeat,
            probes: self.probes,
            aborted: self.aborted,
            secs: now.saturating_duration_since(self.started).as_secs(),
            failures: self.failures.clone(),
            dominant: self.failures.dominant(self.last),
            last: self.last,
            server_ips: self.server_ips.len(),
            hint: self.hint(),
        }
    }
}

/// The hint of a failing run: with servers registered, `no_server` means
/// that every one was used in the last 90 s, typically by retries.
pub(crate) fn hint_for(
    dominant: ProbeFailure,
    hint: &'static str,
    servers: usize,
) -> Cow<'static, str> {
    match dominant {
        ProbeFailure::NoServer if servers > 0 => Cow::Owned(format!(
            "all {servers} servers used in the last 90 s; see the other classes"
        )),
        _ => Cow::Borrowed(hint),
    }
}

/// Follows AutoNAT's probe outcomes and status changes for operator lines.
pub(crate) struct AutonatHealth {
    /// The previous status line, or start.
    status_line_at: Instant,
    /// Whether a status line was logged yet.
    status_logged: bool,
    /// The status that line reported.
    logged_status: &'static str,
    /// Flips since that line, not logged on their own.
    suppressed_flips: u32,
    probes_in_status: u32,
    failures_in_status: FailureCounts,
    run: Option<Run>,
}

pub(crate) fn status_str(status: &NatStatus) -> &'static str {
    match status {
        NatStatus::Public(_) => "public",
        NatStatus::Private => "private",
        NatStatus::Unknown => "unknown",
    }
}

impl AutonatHealth {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            status_line_at: now,
            status_logged: false,
            logged_status: "unknown",
            suppressed_flips: 0,
            probes_in_status: 0,
            failures_in_status: FailureCounts::default(),
            run: None,
        }
    }

    /// A probe failed with `failure`; `server_ip` is its server's IP.
    pub(crate) fn on_failure(
        &mut self,
        failure: ProbeFailure,
        server_ip: Option<IpAddr>,
        now: Instant,
    ) -> Option<AutonatNotice> {
        let sent = failure.sent();
        if sent {
            self.probes_in_status += 1;
        }
        self.failures_in_status.add(failure);
        let run = self.run.get_or_insert_with(|| Run {
            started: now,
            probes: 0,
            aborted: 0,
            failures: FailureCounts::default(),
            last: failure,
            server_ips: HashSet::new(),
            unreachable_ips: HashSet::new(),
            last_line: None,
            inconclusive_since_line: false,
        });
        if sent {
            run.probes += 1;
        } else {
            run.aborted += 1;
        }
        run.failures.add(failure);
        run.last = failure;
        if let Some(ip) = server_ip {
            run.server_ips.insert(ip);
            if failure.unreachable_class() {
                run.unreachable_ips.insert(ip);
            }
        }
        if !failure.unreachable_class() {
            run.inconclusive_since_line = true;
        }
        // Aborted attempts are no probes; they open a run on their own only
        // when no request goes out at all.
        let first_due =
            run.probes >= FAILING_AFTER || (run.probes == 0 && run.aborted >= FAILING_AFTER);
        let last_line = run.last_line;
        match last_line {
            None if first_due => Some(run.notice(now, false)),
            // Once servers on distinct IPs found the node unreachable, that
            // condition is the publisher's warning: repeat only for other
            // failures.
            Some(last)
                if now >= last + FAILING_REPEAT
                    && (run.inconclusive_since_line || !run.unreachable()) =>
            {
                Some(run.notice(now, true))
            }
            _ => None,
        }
    }

    /// A server dialed us back.
    pub(crate) fn on_success(&mut self, now: Instant) -> Option<AutonatNotice> {
        self.probes_in_status += 1;
        let run = self.run.take()?;
        run.last_line.map(|_| AutonatNotice::Recovered {
            probes: run.probes,
            secs: now.saturating_duration_since(run.started).as_secs(),
            failures: run.failures,
        })
    }

    /// AutoNAT's status flipped to `new`: a line, unless one was logged in
    /// the last [`STATUS_LINE_EVERY`].
    pub(crate) fn on_status_changed(
        &mut self,
        new: &NatStatus,
        now: Instant,
    ) -> Option<AutonatNotice> {
        if self.status_line_due(now) {
            return Some(self.status_line(status_str(new), now));
        }
        self.suppressed_flips += 1;
        None
    }

    /// After a probe: the line owed for flips suppressed earlier, once
    /// [`STATUS_LINE_EVERY`] has passed; `nat` is the current status.
    pub(crate) fn flush_status(&mut self, nat: &NatStatus, now: Instant) -> Option<AutonatNotice> {
        (self.suppressed_flips > 0 && self.status_line_due(now))
            .then(|| self.status_line(status_str(nat), now))
    }

    fn status_line_due(&self, now: Instant) -> bool {
        !self.status_logged || now >= self.status_line_at + STATUS_LINE_EVERY
    }

    fn status_line(&mut self, new: &'static str, now: Instant) -> AutonatNotice {
        let notice = AutonatNotice::StatusChanged {
            old: self.logged_status,
            new,
            previous_secs: now.saturating_duration_since(self.status_line_at).as_secs(),
            probes: std::mem::take(&mut self.probes_in_status),
            failures: std::mem::take(&mut self.failures_in_status),
            suppressed_flips: std::mem::take(&mut self.suppressed_flips),
        };
        self.status_line_at = now;
        self.status_logged = true;
        self.logged_status = new;
        notice
    }

    /// The failure counts of the probes since the last dial-back
    /// (`dial_error=6`), `none` when the latest probe brought one.
    pub(crate) fn run_failures(&self) -> String {
        self.run
            .as_ref()
            .map_or_else(|| "none".to_string(), |run| run.failures.to_string())
    }

    /// AutoNAT's view for the PeerInfo publisher.
    pub(crate) fn summary(&self, nat: &NatStatus) -> AutonatSummary {
        AutonatSummary {
            nat_status: status_str(nat),
            probe_failure: self.run.as_ref().map(|run| ProbeFailureSummary {
                class: run.failures.dominant(run.last).as_str(),
                probes: run.probes,
                since: run.started,
                unreachable: run.unreachable(),
            }),
        }
    }
}

/// The swarm's AutoNAT state when a notice is logged.
pub(crate) struct ProbeContext {
    /// Servers the next probe can choose from (registered, not used in the
    /// last 90 s).
    pub(crate) eligible_servers: usize,
    /// Registered servers.
    pub(crate) servers: usize,
    /// Addresses in the latest probe request.
    pub(crate) addresses_sent: usize,
    pub(crate) confidence: usize,
}

/// Whether a failing-probes line is a warning: a repeat, unless servers
/// mostly declined to dial back, which they do at their own connection
/// limits and which tells nothing about this node.
fn failing_is_warning(repeat: bool, dominant: ProbeFailure) -> bool {
    repeat && dominant != ProbeFailure::DialRefused
}

/// Log `notice`. These lines concern this node's own reachability.
pub(crate) fn log(notice: &AutonatNotice, ctx: &ProbeContext) {
    match notice {
        AutonatNotice::StatusChanged {
            old,
            new,
            previous_secs,
            probes,
            failures,
            suppressed_flips,
        } => info!(
            old,
            new,
            confidence = ctx.confidence,
            previous_secs,
            probes,
            failures = %failures,
            suppressed_flips,
            eligible_servers = ctx.eligible_servers,
            servers = ctx.servers,
            "AutoNAT status of this node changed"
        ),
        AutonatNotice::Failing {
            repeat,
            probes,
            aborted,
            secs,
            failures,
            dominant,
            last,
            server_ips,
            hint,
        } => {
            let hint = hint_for(*dominant, *hint, ctx.servers);
            macro_rules! failing {
                ($level:ident, $msg:literal) => {
                    $level!(
                        probes,
                        aborted,
                        failing_secs = secs,
                        failures = %failures,
                        probe_failure = dominant.as_str(),
                        last_failure = last.as_str(),
                        server_ips,
                        eligible_servers = ctx.eligible_servers,
                        servers = ctx.servers,
                        addresses_sent = ctx.addresses_sent,
                        hint = %hint,
                        $msg
                    )
                };
            }
            if failing_is_warning(*repeat, *dominant) {
                failing!(warn, "AutoNAT probes of this node are still failing")
            } else if *repeat {
                failing!(info, "AutoNAT probes of this node are still failing")
            } else {
                failing!(info, "AutoNAT probes of this node are failing")
            }
        }
        AutonatNotice::Recovered {
            probes,
            secs,
            failures,
        } => info!(
            probes,
            failing_secs = secs,
            failures = %failures,
            "AutoNAT probes of this node succeed again"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ProbeFailure::*;

    fn ip(s: &str) -> Option<IpAddr> {
        Some(s.parse().unwrap())
    }

    #[test]
    fn errors_are_classified() {
        let cases = [
            (OutboundProbeError::NoServer, NoServer),
            (OutboundProbeError::NoAddresses, NoAddresses),
            (
                OutboundProbeError::OutboundRequest(OutboundFailure::Timeout),
                Timeout,
            ),
            (
                OutboundProbeError::OutboundRequest(OutboundFailure::DialFailure),
                DialFailure,
            ),
            (
                OutboundProbeError::OutboundRequest(OutboundFailure::ConnectionClosed),
                ConnectionClosed,
            ),
            (
                OutboundProbeError::OutboundRequest(OutboundFailure::UnsupportedProtocols),
                UnsupportedProtocol,
            ),
            (
                OutboundProbeError::OutboundRequest(OutboundFailure::Io(std::io::Error::other(
                    "closed",
                ))),
                Io,
            ),
            (
                OutboundProbeError::Response(ResponseError::DialError),
                DialError,
            ),
            (
                OutboundProbeError::Response(ResponseError::DialRefused),
                DialRefused,
            ),
            (
                OutboundProbeError::Response(ResponseError::BadRequest),
                BadRequest,
            ),
            (
                OutboundProbeError::Response(ResponseError::InternalError),
                Internal,
            ),
        ];
        for (error, class) in cases {
            assert_eq!(ProbeFailure::of(&error), class, "{error:?}");
        }
        for (i, class) in CLASSES.into_iter().enumerate() {
            assert_eq!(class as usize, i);
        }
    }

    #[test]
    fn counts_render_most_frequent_first() {
        let mut counts = FailureCounts::default();
        assert_eq!(counts.to_string(), "none");
        for c in [Io, Timeout, Timeout, DialError, Timeout] {
            counts.add(c);
        }
        assert_eq!(counts.to_string(), "timeout=3 io=1 dial_error=1");
        assert_eq!(counts.dominant(Io), Timeout);
        let mut tie = FailureCounts::default();
        tie.add(Io);
        tie.add(DialError);
        assert_eq!(tie.dominant(DialError), DialError);
        assert_eq!(tie.dominant(Io), Io);
    }

    /// The first line at the third failure, then at most one per ten
    /// minutes, each with the run's counts.
    #[test]
    fn a_failing_run_is_reported_at_onset_then_every_ten_minutes() {
        let t0 = Instant::now();
        let mut health = AutonatHealth::new(t0);
        let mut lines = Vec::new();
        for i in 0..50u64 {
            let at = t0 + Duration::from_secs(30 * i);
            if let Some(notice) = health.on_failure(Timeout, ip("192.0.2.1"), at) {
                lines.push((30 * i, notice));
            }
        }
        let times: Vec<u64> = lines.iter().map(|(t, _)| *t).collect();
        assert_eq!(times, vec![60, 660, 1_260]);
        match &lines[0].1 {
            AutonatNotice::Failing {
                repeat,
                probes,
                secs,
                failures,
                dominant,
                server_ips,
                hint,
                ..
            } => {
                assert!(!repeat);
                assert_eq!((*probes, *secs, *server_ips), (3, 60, 1));
                assert_eq!(failures.to_string(), "timeout=3");
                assert_eq!(*dominant, Timeout);
                assert!(
                    hint.contains("check the port forward of the p2p port first"),
                    "{hint}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            lines[1].1,
            AutonatNotice::Failing {
                repeat: true,
                probes: 23,
                ..
            }
        ));
    }

    #[test]
    fn a_success_ends_the_run_with_one_line_only_after_a_report() {
        let t0 = Instant::now();
        let mut health = AutonatHealth::new(t0);
        assert_eq!(health.on_failure(NoServer, None, t0), None);
        assert_eq!(health.on_success(t0 + Duration::from_secs(5)), None);
        assert_eq!(health.summary(&NatStatus::Unknown).probe_failure, None);
        for i in 0..4 {
            health.on_failure(Io, ip("192.0.2.1"), t0 + Duration::from_secs(10 + i));
        }
        let failures = {
            let mut c = FailureCounts::default();
            (0..4).for_each(|_| c.add(Io));
            c
        };
        assert_eq!(
            health.on_success(t0 + Duration::from_secs(100)),
            Some(AutonatNotice::Recovered {
                probes: 4,
                secs: 90,
                failures
            })
        );
        assert_eq!(health.on_success(t0 + Duration::from_secs(200)), None);
    }

    /// Dial-backs that fail from servers on two IPs mean this node is
    /// unreachable: one line naming the port forward, no repeats.
    #[test]
    fn failed_dial_backs_from_two_ips_point_to_the_port_forward() {
        let t0 = Instant::now();
        let mut health = AutonatHealth::new(t0);
        let servers = ["192.0.2.1", "192.0.2.1", "198.51.100.2"];
        let mut lines = Vec::new();
        for i in 0..40u64 {
            let server = ip(servers[(i as usize).min(2)]);
            if let Some(n) = health.on_failure(DialError, server, t0 + Duration::from_secs(90 * i))
            {
                lines.push(n);
            }
        }
        assert_eq!(lines.len(), 1, "{lines:?}");
        match &lines[0] {
            AutonatNotice::Failing { hint, .. } => assert!(hint.contains("port forward"), "{hint}"),
            other => panic!("{other:?}"),
        }
        let summary = health.summary(&NatStatus::Private);
        assert_eq!(summary.nat_status, "private");
        let failing = summary.probe_failure.unwrap();
        assert_eq!(
            (failing.class, failing.probes, failing.unreachable),
            ("dial_error", 40, true)
        );
    }

    /// A NAT that drops dial-backs silently gives timeouts, not dial errors:
    /// from servers on two IPs they mean unreachable, and the hint points to
    /// the port forward, not to a defect.
    #[test]
    fn timeouts_from_two_ips_mean_unreachable() {
        let t0 = Instant::now();
        let mut health = AutonatHealth::new(t0);
        let mut lines = Vec::new();
        for i in 0..30u64 {
            let server = if i % 2 == 0 {
                ip("192.0.2.1")
            } else {
                ip("198.51.100.2")
            };
            if let Some(n) = health.on_failure(Timeout, server, t0 + Duration::from_secs(30 * i)) {
                lines.push(n);
            }
        }
        let failing = health.summary(&NatStatus::Unknown).probe_failure.unwrap();
        assert_eq!((failing.class, failing.unreachable), ("timeout", true));
        // The onset only: an unreachable node is the publisher's warning.
        assert_eq!(lines.len(), 1, "{lines:?}");
        match &lines[0] {
            AutonatNotice::Failing { hint, .. } => {
                assert!(!hint.contains("does not help"), "{hint}");
                assert!(hint.contains("port forward"), "{hint}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// Only failures with no bearing on reachability rule a port forward out.
    #[test]
    fn only_request_defects_rule_out_a_port_forward() {
        for class in [Io, BadRequest, Internal, UnsupportedProtocol] {
            let mut health = AutonatHealth::new(Instant::now());
            let notice =
                (0..3).find_map(|_| health.on_failure(class, ip("192.0.2.1"), Instant::now()));
            match notice {
                Some(AutonatNotice::Failing { hint, .. }) => {
                    assert!(
                        hint.contains("a port forward does not help"),
                        "{class:?}: {hint}"
                    )
                }
                other => panic!("{class:?}: {other:?}"),
            }
        }
        for class in [
            Timeout,
            ConnectionClosed,
            DialFailure,
            DialRefused,
            DialError,
        ] {
            let mut health = AutonatHealth::new(Instant::now());
            let notice =
                (0..3).find_map(|_| health.on_failure(class, ip("192.0.2.1"), Instant::now()));
            match notice {
                Some(AutonatNotice::Failing { hint, .. }) => {
                    assert!(!hint.contains("does not help"), "{class:?}: {hint}")
                }
                other => panic!("{class:?}: {other:?}"),
            }
        }
    }

    /// Declined dial-backs are routine: never a warning, and no request to
    /// report them.
    #[test]
    fn declined_dial_backs_are_not_a_warning() {
        assert!(!failing_is_warning(false, DialRefused));
        assert!(!failing_is_warning(true, DialRefused));
        assert!(failing_is_warning(true, Timeout));
        assert!(!failing_is_warning(false, Timeout));
        let mut health = AutonatHealth::new(Instant::now());
        let notice =
            (0..3).find_map(|_| health.on_failure(DialRefused, ip("192.0.2.1"), Instant::now()));
        match notice {
            Some(AutonatNotice::Failing { hint, .. }) => {
                assert!(
                    hint.contains("no action needed") && !hint.contains("report"),
                    "{hint}"
                )
            }
            other => panic!("{other:?}"),
        }
    }

    /// `no_server` and `no_addresses` abort before a request: they are no
    /// probes, and open a run only when no request goes out at all.
    #[test]
    fn aborted_attempts_are_not_probes() {
        let t0 = Instant::now();
        let mut health = AutonatHealth::new(t0);
        assert_eq!(health.on_failure(Timeout, ip("192.0.2.1"), t0), None);
        assert_eq!(health.on_failure(NoServer, None, t0), None);
        assert_eq!(health.on_failure(NoServer, None, t0), None);
        assert_eq!(
            health
                .summary(&NatStatus::Unknown)
                .probe_failure
                .unwrap()
                .probes,
            1
        );
        match health.on_failure(Timeout, ip("198.51.100.2"), t0) {
            None => {}
            other => panic!("two probes only: {other:?}"),
        }
        // No server at all: aborted attempts alone open the run.
        let mut alone = AutonatHealth::new(t0);
        assert_eq!(alone.on_failure(NoServer, None, t0), None);
        assert_eq!(alone.on_failure(NoServer, None, t0), None);
        match alone.on_failure(NoServer, None, t0) {
            Some(AutonatNotice::Failing {
                probes: 0,
                aborted: 3,
                ..
            }) => {}
            other => panic!("{other:?}"),
        }
    }

    /// With servers registered, `no_server` means they were all used in the
    /// last 90 s.
    #[test]
    fn the_no_server_hint_tells_throttled_servers_from_none() {
        let hint = "no connected peer serves AutoNAT; check this node's peer connections";
        assert_eq!(hint_for(NoServer, hint, 0), hint);
        assert_eq!(
            hint_for(NoServer, hint, 7),
            "all 7 servers used in the last 90 s; see the other classes"
        );
        assert_eq!(hint_for(Timeout, "x", 7), "x");
    }

    /// One operator's IP is not enough to call the node unreachable.
    #[test]
    fn failed_dial_backs_from_one_ip_do_not_mean_unreachable() {
        let t0 = Instant::now();
        let mut health = AutonatHealth::new(t0);
        for i in 0..5 {
            health.on_failure(DialError, ip("192.0.2.1"), t0 + Duration::from_secs(i));
        }
        let failing = health.summary(&NatStatus::Private).probe_failure.unwrap();
        assert!(!failing.unreachable);
        assert_eq!(failing.class, "dial_error");
    }

    #[test]
    fn a_status_change_reports_the_window_since_the_previous_line() {
        let t0 = Instant::now();
        let mut health = AutonatHealth::new(t0);
        health.on_failure(Timeout, ip("192.0.2.1"), t0 + Duration::from_secs(20));
        health.on_failure(NoServer, None, t0 + Duration::from_secs(25));
        health.on_success(t0 + Duration::from_secs(40));
        let public = NatStatus::Public("/ip4/203.0.113.7/tcp/8336".parse().unwrap());
        let mut failures = FailureCounts::default();
        failures.add(Timeout);
        failures.add(NoServer);
        assert_eq!(
            health.on_status_changed(&public, t0 + Duration::from_secs(40)),
            Some(AutonatNotice::StatusChanged {
                old: "unknown",
                new: "public",
                previous_secs: 40,
                probes: 2,
                failures,
                suppressed_flips: 0,
            })
        );
    }

    /// A flapping status logs at most one line per ten minutes; the next
    /// line counts the flips in between and names the current status.
    #[test]
    fn status_lines_are_rate_limited() {
        let t0 = Instant::now();
        let at = |s| t0 + Duration::from_secs(s);
        let mut health = AutonatHealth::new(t0);
        let public = NatStatus::Public("/ip4/203.0.113.7/tcp/8336".parse().unwrap());
        assert!(health.on_status_changed(&public, at(5)).is_some());
        assert_eq!(health.on_status_changed(&NatStatus::Private, at(60)), None);
        assert_eq!(health.on_status_changed(&public, at(120)), None);
        assert_eq!(health.flush_status(&public, at(300)), None);
        match health.flush_status(&public, at(700)) {
            Some(AutonatNotice::StatusChanged {
                old: "public",
                new: "public",
                previous_secs: 695,
                suppressed_flips: 2,
                ..
            }) => {}
            other => panic!("{other:?}"),
        }
        assert_eq!(health.flush_status(&public, at(2_000)), None);
        // A flip after the interval logs at once.
        assert!(matches!(
            health.on_status_changed(&NatStatus::Private, at(2_100)),
            Some(AutonatNotice::StatusChanged {
                old: "public",
                new: "private",
                suppressed_flips: 0,
                ..
            })
        ));
    }

    /// The hold lines carry the failures since the last dial-back.
    #[test]
    fn run_failures_count_the_probes_since_the_last_dial_back() {
        let t0 = Instant::now();
        let mut health = AutonatHealth::new(t0);
        assert_eq!(health.run_failures(), "none");
        health.on_failure(DialError, ip("192.0.2.1"), t0);
        health.on_failure(DialError, ip("192.0.2.2"), t0);
        health.on_failure(Timeout, ip("192.0.2.3"), t0);
        assert_eq!(health.run_failures(), "dial_error=2 timeout=1");
        health.on_success(t0);
        assert_eq!(health.run_failures(), "none");
    }

    /// Only a server's failed or timed-out dial-back counts against an
    /// address.
    #[test]
    fn only_failed_dial_backs_count_against_an_address() {
        use crate::external_addr::ProbeMiss;
        for class in CLASSES {
            let expected = match class {
                DialError | Timeout => ProbeMiss::Unreachable,
                _ => ProbeMiss::Inconclusive,
            };
            assert_eq!(class.miss(), expected, "{class:?}");
        }
    }
}
