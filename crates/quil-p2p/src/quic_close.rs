//! Operator lines on QUIC connections that end on a transport error.
//!
//! A QUIC connection ends on a transport error when the QUIC stack of either
//! side gives up on it, as opposed to an application close, a peer restart or
//! an idle link. Under heavy packet loss the receiving side can hold more gaps
//! in a stream than its QUIC stack allows, and then closes the connection with
//! `too many gaps in stream buffer`. Both sides reconnect by themselves and
//! the closes repeat while the loss lasts, so the first close of an interval
//! is logged at once and the later ones in one summary line when the interval
//! ends.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use libp2p::core::ConnectedPoint;
use libp2p::swarm::{ConnectionError, ConnectionId};
use libp2p::{Multiaddr, PeerId};
use tracing::warn;

/// Closes after the first one within this interval go into one summary line.
pub(crate) const SUMMARY_INTERVAL: Duration = Duration::from_secs(600);
/// The longest close reason logged, in characters: the peer chooses part of it.
const REASON_CHARS: usize = 160;
/// Distinct peers counted for a summary line.
const PEERS_COUNTED: usize = 512;
/// quinn's text for the `NO_ERROR` code.
const NO_ERROR: &str = "the connection is being closed abruptly in the absence of any error";

/// Which side's QUIC stack ended the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClosedBy {
    ThisNode,
    Peer,
}

impl ClosedBy {
    fn as_str(self) -> &'static str {
        match self {
            Self::ThisNode => "this node",
            Self::Peer => "the peer",
        }
    }
}

/// The transport error a QUIC connection ended on and the side that ended it;
/// `None` for every other end and for TCP connections.
pub(crate) fn transport_error(cause: &ConnectionError) -> Option<(ClosedBy, String)> {
    let ConnectionError::IO(io) = cause else {
        return None;
    };
    match io.get_ref()?.downcast_ref::<libp2p::quic::Error>()? {
        libp2p::quic::Error::Connection(e) => classify(&e.to_string()),
        _ => None,
    }
}

/// Reads quinn's text for how a connection ended (the `Display` of
/// `quinn::ConnectionError`, which libp2p-quic keeps private).
fn classify(text: &str) -> Option<(ClosedBy, String)> {
    // An application close by this node or the peer, a restarted peer, an idle
    // link, and two ends no link causes.
    const ORDINARY: [&str; 5] = [
        "closed",
        "reset by peer",
        "timed out",
        "CIDs exhausted",
        "peer doesn't implement any supported version",
    ];
    if ORDINARY.contains(&text) || text.starts_with("closed by peer: ") {
        return None;
    }
    let (closed_by, reason) = match text.strip_prefix("aborted by peer: ") {
        Some(reason) => (ClosedBy::Peer, reason),
        None => (ClosedBy::ThisNode, text),
    };
    if reason.starts_with(NO_ERROR) {
        return None;
    }
    Some((closed_by, bounded(reason)))
}

/// At most `REASON_CHARS` characters, on one line.
fn bounded(reason: &str) -> String {
    let mut out: String = reason
        .chars()
        .take(REASON_CHARS)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    if reason.chars().nth(REASON_CHARS).is_some() {
        out.push_str("...");
    }
    out
}

/// A line for the operator.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Line {
    /// The first close of an interval.
    First {
        peer: PeerId,
        remote: Multiaddr,
        closed_by: ClosedBy,
        reason: String,
        age: Duration,
    },
    /// The closes after the first one of an interval, when it ends.
    Summary {
        closes: u64,
        closed_by_peer: u64,
        peers: usize,
        shortest_age: Duration,
        last_reason: String,
        interval: Duration,
    },
}

impl Line {
    pub(crate) fn log(&self) {
        match self {
            Line::First {
                peer,
                remote,
                closed_by,
                reason,
                age,
            } => warn!(
                %peer,
                %remote,
                closed_by = closed_by.as_str(),
                %reason,
                connection_age_secs = age.as_secs(),
                "a QUIC connection closed on a transport error and its streams ended; the node \
                 reconnects by itself. \"too many gaps in stream buffer\" means heavy packet loss \
                 on the link to this peer: check this host's network for packet loss; another \
                 reason names a QUIC fault of the side in closed_by. Further closes within 10 min \
                 go into one summary line"
            ),
            Line::Summary {
                closes,
                closed_by_peer,
                peers,
                shortest_age,
                last_reason,
                interval,
            } => warn!(
                closes,
                closed_by_peer,
                peers,
                shortest_connection_age_secs = shortest_age.as_secs(),
                %last_reason,
                interval_secs = interval.as_secs(),
                "more QUIC connections closed on transport errors in the interval since the first \
                 one was logged; the node reconnects by itself. Repeated \"too many gaps in stream \
                 buffer\" closes mean lasting heavy packet loss: check this host's network"
            ),
        }
    }
}

/// The closes after the first one of the current interval.
struct Interval {
    started: Instant,
    closes: u64,
    closed_by_peer: u64,
    peers: HashSet<PeerId>,
    shortest_age: Option<Duration>,
    last_reason: String,
}

/// Turns the swarm's connection events into at most one line at once and one
/// summary line per `SUMMARY_INTERVAL`.
#[derive(Default)]
pub(crate) struct QuicCloses {
    /// When each open connection was established: as many as the swarm holds.
    opened: HashMap<ConnectionId, Instant>,
    interval: Option<Interval>,
}

impl QuicCloses {
    pub(crate) fn on_established(&mut self, id: ConnectionId, now: Instant) {
        self.opened.insert(id, now);
    }

    /// The lines a closed connection gives: none, the first of an interval,
    /// or the summary of the last interval and the first of a new one.
    pub(crate) fn on_closed(
        &mut self,
        id: ConnectionId,
        peer: PeerId,
        endpoint: &ConnectedPoint,
        cause: Option<&ConnectionError>,
        now: Instant,
    ) -> Vec<Line> {
        let age = self.age_of(id, now);
        match cause.and_then(transport_error) {
            Some((closed_by, reason)) => self.record(
                peer,
                endpoint.get_remote_address().clone(),
                closed_by,
                reason,
                age.unwrap_or_default(),
                now,
            ),
            None => Vec::new(),
        }
    }

    /// The summary of an interval that has ended, if it had closes after its
    /// first one.
    pub(crate) fn on_tick(&mut self, now: Instant) -> Option<Line> {
        let ended = self
            .interval
            .as_ref()
            .is_some_and(|i| now.saturating_duration_since(i.started) >= SUMMARY_INTERVAL);
        if !ended {
            return None;
        }
        let i = self.interval.take()?;
        (i.closes > 0).then(|| Line::Summary {
            closes: i.closes,
            closed_by_peer: i.closed_by_peer,
            peers: i.peers.len(),
            shortest_age: i.shortest_age.unwrap_or_default(),
            last_reason: i.last_reason,
            interval: now.saturating_duration_since(i.started),
        })
    }

    fn age_of(&mut self, id: ConnectionId, now: Instant) -> Option<Duration> {
        self.opened
            .remove(&id)
            .map(|at| now.saturating_duration_since(at))
    }

    fn record(
        &mut self,
        peer: PeerId,
        remote: Multiaddr,
        closed_by: ClosedBy,
        reason: String,
        age: Duration,
        now: Instant,
    ) -> Vec<Line> {
        let mut lines: Vec<Line> = self.on_tick(now).into_iter().collect();
        if let Some(i) = self.interval.as_mut() {
            i.closes += 1;
            if closed_by == ClosedBy::Peer {
                i.closed_by_peer += 1;
            }
            if i.peers.len() < PEERS_COUNTED {
                i.peers.insert(peer);
            }
            i.shortest_age = Some(i.shortest_age.map_or(age, |s| s.min(age)));
            i.last_reason = reason;
            return lines;
        }
        self.interval = Some(Interval {
            started: now,
            closes: 0,
            closed_by_peer: 0,
            peers: HashSet::new(),
            shortest_age: None,
            last_reason: String::new(),
        });
        lines.push(Line::First {
            peer,
            remote,
            closed_by,
            reason,
            age,
        });
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAPS: &str = "the endpoint encountered an internal error and cannot continue with the \
                        connection: too many gaps in stream buffer";

    fn record(c: &mut QuicCloses, peer: PeerId, closed_by: ClosedBy, now: Instant) -> Vec<Line> {
        let remote: Multiaddr = "/ip4/192.0.2.7/udp/8336/quic-v1".parse().unwrap();
        c.record(
            peer,
            remote,
            closed_by,
            GAPS.to_string(),
            Duration::from_secs(3),
            now,
        )
    }

    #[test]
    fn ordinary_closes_are_not_transport_errors() {
        let aborted_without_error = format!("aborted by peer: {NO_ERROR}");
        for text in [
            "closed",
            "closed by peer: 0",
            "closed by peer: going away (code 7)",
            "reset by peer",
            "timed out",
            "CIDs exhausted",
            "peer doesn't implement any supported version",
            NO_ERROR,
            aborted_without_error.as_str(),
        ] {
            assert_eq!(
                classify(text),
                None,
                "an ordinary close was taken for a transport error: {text}"
            );
        }
    }

    #[test]
    fn transport_errors_name_the_side_that_ended_the_connection() {
        assert_eq!(
            classify(GAPS),
            Some((ClosedBy::ThisNode, GAPS.to_string())),
            "a close by this node was put on the wrong side"
        );
        assert_eq!(
            classify(&format!("aborted by peer: {GAPS}")),
            Some((ClosedBy::Peer, GAPS.to_string())),
            "a close by the peer was put on the wrong side"
        );
    }

    #[test]
    fn a_reason_the_peer_chose_is_bounded_and_kept_on_one_line() {
        let long = format!("aborted by peer: a\nb{}", "c".repeat(10_000));
        let (_, reason) = classify(&long).expect("a transport error");
        assert!(
            reason.chars().count() <= REASON_CHARS + 3 && !reason.chars().any(char::is_control),
            "the logged reason is unbounded or spans lines: {} chars",
            reason.chars().count()
        );
    }

    #[test]
    fn a_connection_age_runs_from_its_establishment() {
        let mut c = QuicCloses::default();
        let t0 = Instant::now();
        let id = ConnectionId::new_unchecked(7);
        c.on_established(id, t0);
        assert_eq!(
            c.age_of(id, t0 + Duration::from_secs(42)),
            Some(Duration::from_secs(42)),
            "the connection age was lost"
        );
        assert_eq!(c.age_of(id, t0), None, "a closed connection stays tracked");
    }

    #[test]
    fn closes_after_the_first_are_summed_once_per_interval() {
        let mut c = QuicCloses::default();
        let t0 = Instant::now();
        let (a, b) = (PeerId::random(), PeerId::random());
        let at = |secs| t0 + Duration::from_secs(secs);
        let first = record(&mut c, a, ClosedBy::ThisNode, t0);
        assert!(
            matches!(first.as_slice(), [Line::First { peer, age, .. }] if *peer == a && age.as_secs() == 3),
            "the first close did not give its line: {first:?}"
        );
        assert!(
            record(&mut c, b, ClosedBy::ThisNode, at(1)).is_empty()
                && record(&mut c, b, ClosedBy::Peer, at(2)).is_empty(),
            "a repeated close within the interval logged its own line"
        );
        assert_eq!(c.on_tick(at(599)), None, "the interval ended early");
        let summary = c.on_tick(at(600));
        assert!(
            matches!(
                summary,
                Some(Line::Summary {
                    closes: 2,
                    closed_by_peer: 1,
                    peers: 1,
                    ..
                })
            ),
            "the closes after the first were not summed at the end of the interval: {summary:?}"
        );
        assert_eq!(c.on_tick(at(700)), None, "an interval was summed twice");
        // A close after a quiet interval is a first again, and alone gives no summary.
        assert!(matches!(
            record(&mut c, a, ClosedBy::ThisNode, at(701)).as_slice(),
            [Line::First { .. }]
        ));
        assert_eq!(c.on_tick(at(1301)), None, "a lone close was summed");
        // A close past the end of an interval with repeats sums that interval first.
        record(&mut c, a, ClosedBy::ThisNode, at(1400));
        record(&mut c, b, ClosedBy::ThisNode, at(1401));
        let lines = record(&mut c, a, ClosedBy::ThisNode, at(2000));
        assert!(
            matches!(
                lines.as_slice(),
                [Line::Summary { closes: 1, .. }, Line::First { .. }]
            ),
            "the closes after the first were not summed before a new interval: {lines:?}"
        );
    }
}
