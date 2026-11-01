//! The node's current AutoNAT-confirmed external address, one per transport.
//!
//! AutoNAT v1 reports the address each dial-back server reached us at. The
//! swarm keeps every address it has ever confirmed, but PeerInfo must carry
//! the current one: after a dynamic-IP change the old address is useless to
//! the peers that dial it. [`ExternalAddrTracker`] keeps, per transport, the
//! latest confirmed address that is globally routable and on one of our listen
//! ports. It moves an established address to a different IP only once two
//! servers on distinct IPs confirm the new one, so a single dishonest
//! operator, however many nodes it runs behind one IP, cannot redirect the
//! peers that dial us.
//!
//! AutoNAT's status alone neither adds nor drops an address. A server that
//! does not run this repository's AutoNAT patch answers a dial-back it
//! refused itself (it already holds two connections to us, or another dial
//! to us failed meanwhile) as a failed dial, so a reachable node sees most
//! probes fail and AutoNAT holds it private while servers still reach it now
//! and then; and a node whose port forward broke while AutoNAT held it public
//! sees its probes time out, which leaves the status public. So every
//! dial-back confirms its address whatever the status, and an address goes
//! once [`KEEP_UNCONFIRMED`] has passed without a confirmation and
//! [`DROP_AFTER_UNREACHABLE`] probes since the last one found the node
//! unreachable.
//!
//! The swarm's expiry signal is handled too, but nothing emits it today:
//! AutoNAT v1 only confirms, and the node never calls
//! `remove_external_address`.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use libp2p::autonat::NatStatus;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use tracing::{info, warn};

/// The transports the node listens on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExternalTransport {
    Tcp,
    Quic,
}

impl ExternalTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            ExternalTransport::Tcp => "tcp",
            ExternalTransport::Quic => "quic",
        }
    }
}

/// The event behind the latest change of the confirmed set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalAddrChange {
    /// An AutoNAT server dialed us back on an address we did not hold.
    Confirmed,
    /// The swarm expired a confirmed address (nothing emits this today).
    Expired,
    /// No server confirmed the address for [`KEEP_UNCONFIRMED`] while
    /// AutoNAT did not hold the node public.
    Stale,
}

impl ExternalAddrChange {
    pub fn as_str(self) -> &'static str {
        match self {
            ExternalAddrChange::Confirmed => "confirmed",
            ExternalAddrChange::Expired => "expired",
            ExternalAddrChange::Stale => "not_reconfirmed",
        }
    }
}

/// The current confirmed external addresses, as published to the node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConfirmedExternalAddrs {
    /// At most one address per transport, most recently accepted first,
    /// without a trailing `/p2p/...`.
    pub addrs: Vec<String>,
    /// What changed `addrs` last; `None` until the first change.
    pub last_change: Option<ExternalAddrChange>,
    /// AutoNAT's view behind `addrs`, for operator lines.
    pub autonat: AutonatSummary,
}

/// AutoNAT's view of this node's reachability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutonatSummary {
    /// `public`, `private` or `unknown`.
    pub nat_status: &'static str,
    /// The current run of probes without a dial-back; `None` while the
    /// latest probe brought one, or before any failed.
    pub probe_failure: Option<ProbeFailureSummary>,
}

impl Default for AutonatSummary {
    fn default() -> Self {
        Self {
            nat_status: "unknown",
            probe_failure: None,
        }
    }
}

/// A run of AutoNAT probes without a dial-back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeFailureSummary {
    /// The run's most frequent failure class (`timeout`, `dial_error`, ...).
    pub class: &'static str,
    /// Probes in the run.
    pub probes: u32,
    /// When the run began.
    pub since: std::time::Instant,
    /// Servers on distinct IPs dialed this node back and reached none of
    /// its addresses (`dial_error`), or did not finish within AutoNAT's
    /// timeout (`timeout`, as when a NAT drops the dial-backs): the node is
    /// unreachable, as opposed to probes that fail for other reasons.
    pub unreachable: bool,
}

/// Transport and port of a TCP or QUIC multiaddr.
pub fn transport_and_port(addr: &Multiaddr) -> Option<(ExternalTransport, u16)> {
    let (mut tcp, mut udp, mut quic) = (None, None, false);
    for proto in addr.iter() {
        match proto {
            Protocol::Tcp(port) => tcp = Some(port),
            Protocol::Udp(port) => udp = Some(port),
            Protocol::QuicV1 | Protocol::Quic => quic = true,
            _ => {}
        }
    }
    if quic {
        udp.map(|port| (ExternalTransport::Quic, port))
    } else {
        tcp.map(|port| (ExternalTransport::Tcp, port))
    }
}

/// Transport of a multiaddr string, `None` when it is neither TCP nor QUIC.
pub fn transport_of(addr: &str) -> Option<ExternalTransport> {
    let addr: Multiaddr = addr.parse().ok()?;
    transport_and_port(&addr).map(|(transport, _)| transport)
}

fn without_peer_id(addr: &Multiaddr) -> Multiaddr {
    let mut addr = addr.clone();
    while matches!(addr.iter().last(), Some(Protocol::P2p(_))) {
        addr.pop();
    }
    addr
}

/// What [`ExternalAddrTracker::on_confirmed`] did with an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConfirmOutcome {
    /// Not usable as our address: names no TCP/QUIC transport, a port we do
    /// not listen on, or an IP peers cannot route to.
    Rejected(&'static str),
    /// Already the current address of its transport.
    Unchanged,
    /// A different IP for a transport that has an address; it waits for a
    /// second server on another IP.
    Pending,
    /// The confirmed set changed.
    Accepted,
}

/// The AutoNAT server behind a dial-back: its peer and the remote IP of its
/// connection, when known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProbeServer {
    pub(crate) peer: PeerId,
    pub(crate) ip: Option<IpAddr>,
}

impl ProbeServer {
    /// Distinct peers on distinct known IPs: one operator's nodes behind one
    /// IP (one IPv6 /64, see `autonat_servers::ip_group`) count once.
    fn independent_of(&self, other: &ProbeServer) -> bool {
        self.peer != other.peer && matches!((self.ip, other.ip), (Some(a), Some(b)) if a != b)
    }
}

/// How long a move to a new IP may wait for its second server before a
/// warning.
pub(crate) const PENDING_WARN_AFTER: Duration = Duration::from_secs(30 * 60);

/// How long an address stays without a confirming dial-back: counted from
/// its latest confirmation, or from when AutoNAT stopped holding the node
/// public if that came later, so a public node that probes rarely does not
/// lose its address at the first private verdict. It goes only once
/// [`DROP_AFTER_UNREACHABLE`] probes have also found the node unreachable.
pub(crate) const KEEP_UNCONFIRMED: Duration = Duration::from_secs(60 * 60);

/// How many probes since an address's latest confirmation must have found
/// the node unreachable before it goes: a `dial_error` or `timeout`, or a
/// dial-back that reached another port of the address's transport after
/// the listen port, which servers dial first. Probes that tell nothing
/// (refused, no server, a failed request) do not count, and at most one
/// miss counts per [`MISS_SPACING`].
///
/// AutoNAT probes a node it holds private every 3 min while peers connect to
/// it and every 15 min otherwise. Servers without this repository's AutoNAT
/// patch report the dial-backs they refuse themselves as `dial_error`, and
/// on reachable nodes about one probe in seven came back confirmed. Twelve
/// such probes in a row then happen with about a 16% chance, and with the
/// hour on top a reachable node loses its address about every 7 to 9 hours
/// until its next confirmation, minutes later. As servers upgrade, that
/// falls to the rate of real failures. A node that became unreachable loses
/// its address within one to three hours, depending on its probe rate.
pub(crate) const DROP_AFTER_UNREACHABLE: u32 = 12;

/// The least time between two misses that count against an address.
/// AutoNAT retries a timed-out probe at once, so a short outage of this
/// node's uplink brings a burst of timeouts about 30 s apart; a failed
/// dial-back is retried after AutoNAT's 90 s retry interval. Counting one
/// miss per 90 s makes the twelve misses span at least 16.5 min of failing
/// probes, so a few minutes of lost connectivity cannot drop an address.
pub(crate) const MISS_SPACING: Duration = Duration::from_secs(90);

/// A move of a transport's address to a new IP, waiting for a second server.
struct PendingMove {
    transport: ExternalTransport,
    addr: Multiaddr,
    server: ProbeServer,
    /// When [`ExternalAddrTracker::pending_notices`] first saw it.
    since: Option<Instant>,
    warned: bool,
}

/// An operator line about a pending move.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PendingNotice {
    /// A server confirmed this node at a new IP.
    Started { transport: ExternalTransport },
    /// Still waiting after [`PENDING_WARN_AFTER`].
    Stale {
        transport: ExternalTransport,
        secs: u64,
    },
    /// The move ended: `moved`, `current_reconfirmed`, `replaced`,
    /// `expired`, or `current_dropped`/`current_expired` with its transport's
    /// address.
    Resolved {
        transport: ExternalTransport,
        secs: u64,
        outcome: &'static str,
    },
}

/// Log a pending-move notice. These lines concern this node's own address.
pub(crate) fn log_pending(notice: &PendingNotice) {
    match notice {
        PendingNotice::Started { transport } => info!(
            transport = transport.as_str(),
            "AutoNAT confirmed this node at a new IP; PeerInfo keeps the current address until a \
             server on another IP confirms it"
        ),
        PendingNotice::Stale { transport, secs } => warn!(
            transport = transport.as_str(),
            pending_secs = secs,
            "a new IP of this node still awaits a second AutoNAT server on another IP, so PeerInfo \
             announces the old address; see the 'AutoNAT probes of this node' lines, and report \
             this line if probes succeed"
        ),
        PendingNotice::Resolved {
            transport,
            secs,
            outcome,
        } => info!(
            transport = transport.as_str(),
            pending_secs = secs,
            outcome,
            "pending move of this node's address to a new IP ended"
        ),
    }
}

/// An operator line about keeping or dropping an address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HoldNotice {
    /// AutoNAT holds the node private while `addr` is held; a server
    /// confirmed it `confirmed_secs` ago.
    Kept {
        transport: ExternalTransport,
        addr: String,
        confirmed_secs: u64,
    },
    /// No server confirmed `addr` for `unconfirmed_secs`, and
    /// `unreachable_probes` probes since found the node unreachable, so it
    /// was dropped.
    Dropped {
        transport: ExternalTransport,
        addr: String,
        unconfirmed_secs: u64,
        unreachable_probes: u32,
    },
}

/// Log a hold notice; `failures` counts the failing probes since the last
/// dial-back (`dial_error=6`). These lines concern this node's own address.
pub(crate) fn log_hold(notice: &HoldNotice, nat_status: &'static str, failures: &str) {
    match notice {
        HoldNotice::Kept {
            transport,
            addr,
            confirmed_secs,
        } => info!(
            transport = transport.as_str(),
            address = %addr,
            confirmed_secs,
            nat_status,
            failures,
            keep_secs = KEEP_UNCONFIRMED.as_secs(),
            drop_after_unreachable = DROP_AFTER_UNREACHABLE,
            "this node's AutoNAT probes hold it private, but a server reached it at its address \
             confirmed_secs ago, so PeerInfo keeps announcing the address until keep_secs pass \
             without a confirmation and drop_after_unreachable probes find the node unreachable; \
             a server that already holds two connections to this node refuses its dial-back, and \
             one without the AutoNAT fix reports that as a failed dial, so this is expected on a \
             reachable node. A static public address can be set with p2p.announceListenMultiaddr \
             and p2p.announceStreamListenMultiaddr"
        ),
        HoldNotice::Dropped {
            transport,
            addr,
            unconfirmed_secs,
            unreachable_probes,
        } => warn!(
            transport = transport.as_str(),
            address = %addr,
            unconfirmed_secs,
            unreachable_probes,
            nat_status,
            failures,
            "no AutoNAT server has reached this node at its address for unconfirmed_secs, and \
             unreachable_probes probes since found it unreachable, so PeerInfo stops announcing \
             it and peers may be unable to dial the node until a server confirms it again; check \
             that the p2p and stream ports are forwarded to this node, or set \
             p2p.announceListenMultiaddr and p2p.announceStreamListenMultiaddr for a static \
             public address"
        ),
    }
}

/// What a probe without a dial-back tells about this node's reachability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProbeMiss {
    /// A server could not dial this node back (`dial_error`), or not in time
    /// (`timeout`).
    Unreachable,
    /// Nothing: the server refused, the request failed, or no server or
    /// address was available.
    Inconclusive,
}

/// A signal from the swarm event loop to [`ExternalAddrTracker::apply`].
#[derive(Clone, Copy, Debug)]
pub(crate) enum ExternalAddrEvent<'a> {
    /// A probe's server dialed us back on that address.
    Confirmed(&'a Multiaddr, ProbeServer),
    /// A probe brought no dial-back.
    Failed(ProbeMiss),
    /// AutoNAT's status flipped.
    StatusChanged,
    /// The swarm expired one of its confirmed addresses.
    Expired(&'a Multiaddr),
}

/// What [`ExternalAddrTracker::apply`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Applied {
    /// A dial-back from a server, whatever AutoNAT's status.
    Confirm(ConfirmOutcome),
    /// The swarm expired an address (`true` when it was ours).
    Expired(bool),
    /// Nothing changed: a failed probe or a status change keeps every
    /// address (see [`ExternalAddrTracker::expire_unconfirmed`]).
    Nothing,
}

impl Applied {
    /// Whether the confirmed set changed. The swarm loop compares the
    /// published value instead, which also carries AutoNAT's view.
    #[cfg(test)]
    pub(crate) fn changed(self) -> bool {
        matches!(
            self,
            Applied::Confirm(ConfirmOutcome::Accepted) | Applied::Expired(true)
        )
    }
}

/// A transport's current address.
struct Held {
    transport: ExternalTransport,
    addr: Multiaddr,
    /// The latest dial-back that confirmed it.
    confirmed_at: Instant,
    /// Probes since then that found the node unreachable, at most one per
    /// [`MISS_SPACING`].
    unreachable_probes: u32,
    /// When the latest of them counted.
    last_miss_at: Option<Instant>,
}

impl Held {
    /// A probe at `now` found the node unreachable at this address.
    fn miss(&mut self, now: Instant) {
        if self
            .last_miss_at
            .is_some_and(|last| now.saturating_duration_since(last) < MISS_SPACING)
        {
            return;
        }
        self.last_miss_at = Some(now);
        self.unreachable_probes = self.unreachable_probes.saturating_add(1);
    }
}

/// Tracks the current confirmed external address of each transport.
pub(crate) struct ExternalAddrTracker {
    tcp_port: Option<u16>,
    quic_port: Option<u16>,
    routable: fn(&Multiaddr) -> bool,
    /// Most recently accepted first; at most one per transport.
    current: Vec<Held>,
    /// A different address for a transport that has one, with the server
    /// that confirmed it; at most one per transport, and none for a
    /// transport without a current address.
    pending: Vec<PendingMove>,
    /// Moves that ended since the last `pending_notices`, with their start.
    ended: Vec<(ExternalTransport, Option<Instant>, &'static str)>,
    last_change: Option<ExternalAddrChange>,
    /// Whether AutoNAT held the node public at the last event.
    public: bool,
    /// When AutoNAT stopped holding the node public; `None` while it does,
    /// and before it ever did.
    left_public_at: Option<Instant>,
    /// Whether the addresses held since AutoNAT last turned private were
    /// reported kept; cleared when it turns public or nothing is held.
    kept_reported: bool,
    /// Hold lines not yet taken by `hold_notices`.
    holds: Vec<HoldNotice>,
}

impl ExternalAddrTracker {
    /// `tcp_port`/`quic_port` are the ports of our listeners; `routable`
    /// decides which IPs peers can reach.
    pub(crate) fn new(
        tcp_port: Option<u16>,
        quic_port: Option<u16>,
        routable: fn(&Multiaddr) -> bool,
    ) -> Self {
        Self {
            tcp_port,
            quic_port,
            routable,
            current: Vec::new(),
            pending: Vec::new(),
            ended: Vec::new(),
            last_change: None,
            public: false,
            left_public_at: None,
            kept_reported: false,
            holds: Vec::new(),
        }
    }

    /// Apply `event` at `now`, given AutoNAT's status after it.
    ///
    /// A dial-back confirms its address whatever the status: a server
    /// reached us there. A probe that found the node unreachable counts
    /// against every held address, for [`Self::expire_unconfirmed`]. The
    /// status already reflects the probe when its event reaches the swarm:
    /// the behaviour updates it while handling the response and drains its
    /// queued events before handling the next one.
    pub(crate) fn apply(
        &mut self,
        event: ExternalAddrEvent<'_>,
        nat: &NatStatus,
        now: Instant,
    ) -> Applied {
        let applied = match event {
            ExternalAddrEvent::Expired(addr) => Applied::Expired(self.on_expired(addr)),
            ExternalAddrEvent::Confirmed(addr, server) => {
                Applied::Confirm(self.confirm_at(addr, server, now))
            }
            ExternalAddrEvent::Failed(ProbeMiss::Unreachable) => {
                for held in &mut self.current {
                    held.miss(now);
                }
                Applied::Nothing
            }
            ExternalAddrEvent::Failed(ProbeMiss::Inconclusive)
            | ExternalAddrEvent::StatusChanged => Applied::Nothing,
        };
        self.note_status(nat, now);
        applied
    }

    /// Follow AutoNAT's status: when it left public, and one report of the
    /// held addresses when it turns private.
    fn note_status(&mut self, nat: &NatStatus, now: Instant) {
        if nat.is_public() {
            self.public = true;
            self.left_public_at = None;
            self.kept_reported = false;
            return;
        }
        if self.public {
            self.public = false;
            self.left_public_at = Some(now);
        }
        if *nat != NatStatus::Private || self.kept_reported || self.current.is_empty() {
            return;
        }
        self.kept_reported = true;
        // An address past its window goes at the next expiry instead.
        let kept: Vec<HoldNotice> = self
            .current
            .iter()
            .filter(|held| !self.is_stale(held, now))
            .map(|held| HoldNotice::Kept {
                transport: held.transport,
                addr: held.addr.to_string(),
                confirmed_secs: now.saturating_duration_since(held.confirmed_at).as_secs(),
            })
            .collect();
        self.holds.extend(kept);
    }

    /// Whether `held` is due to go at `now`: [`KEEP_UNCONFIRMED`] without a
    /// confirmation, counted from when AutoNAT left public if that came
    /// later, and [`DROP_AFTER_UNREACHABLE`] probes that found the node
    /// unreachable since the confirmation.
    fn is_stale(&self, held: &Held, now: Instant) -> bool {
        let since = self
            .left_public_at
            .map_or(held.confirmed_at, |left| left.max(held.confirmed_at));
        now.saturating_duration_since(since) >= KEEP_UNCONFIRMED
            && held.unreachable_probes >= DROP_AFTER_UNREACHABLE
    }

    /// Drop every address due to go at `now` (see [`Self::is_stale`]),
    /// whatever AutoNAT's status, with the pending move of its transport.
    /// Returns whether the confirmed set changed.
    pub(crate) fn expire_unconfirmed(&mut self, now: Instant) -> bool {
        let mut changed = false;
        let mut i = 0;
        while i < self.current.len() {
            if !self.is_stale(&self.current[i], now) {
                i += 1;
                continue;
            }
            let held = self.current.remove(i);
            if let Some(j) = self
                .pending
                .iter()
                .position(|p| p.transport == held.transport)
            {
                self.end_pending(j, "current_dropped");
            }
            self.holds.push(HoldNotice::Dropped {
                transport: held.transport,
                addr: held.addr.to_string(),
                unconfirmed_secs: now.saturating_duration_since(held.confirmed_at).as_secs(),
                unreachable_probes: held.unreachable_probes,
            });
            changed = true;
        }
        if !changed {
            return false;
        }
        if self.current.is_empty() {
            self.kept_reported = false;
        }
        self.last_change = Some(ExternalAddrChange::Stale);
        true
    }

    /// Hold lines since the last call.
    pub(crate) fn hold_notices(&mut self) -> Vec<HoldNotice> {
        std::mem::take(&mut self.holds)
    }
    /// `server` dialed us back on `address` just now.
    #[cfg(test)]
    fn on_confirmed(&mut self, address: &Multiaddr, server: ProbeServer) -> ConfirmOutcome {
        self.confirm_at(address, server, Instant::now())
    }

    /// `server` dialed us back on `address` at `now`.
    fn confirm_at(
        &mut self,
        address: &Multiaddr,
        server: ProbeServer,
        now: Instant,
    ) -> ConfirmOutcome {
        let addr = without_peer_id(address);
        let Some((transport, port)) = transport_and_port(&addr) else {
            return ConfirmOutcome::Rejected("transport");
        };
        let listen_port = match transport {
            ExternalTransport::Tcp => self.tcp_port,
            ExternalTransport::Quic => self.quic_port,
        };
        if listen_port != Some(port) {
            // Servers dial the listen port first: a dial-back that reached
            // another port means the held address on the listen port did
            // not answer.
            for held in self.current.iter_mut().filter(|h| h.transport == transport) {
                held.miss(now);
            }
            return ConfirmOutcome::Rejected("port");
        }
        if !(self.routable)(&addr) {
            return ConfirmOutcome::Rejected("not_routable");
        }
        let pending = self.pending.iter().position(|p| p.transport == transport);
        let new_move = |addr| PendingMove {
            transport,
            addr,
            server,
            since: None,
            warned: false,
        };
        let held = |addr| Held {
            transport,
            addr,
            confirmed_at: now,
            unreachable_probes: 0,
            last_miss_at: None,
        };
        match self.current.iter().position(|h| h.transport == transport) {
            Some(i) if self.current[i].addr == addr => {
                // A server still sees us here, so a different pending IP
                // was not where peers reach us.
                if let Some(j) = pending {
                    self.end_pending(j, "current_reconfirmed");
                }
                self.current[i].confirmed_at = now;
                self.current[i].unreachable_probes = 0;
                self.current[i].last_miss_at = None;
                ConfirmOutcome::Unchanged
            }
            Some(i) => match pending {
                Some(j)
                    if self.pending[j].addr == addr
                        && self.pending[j].server.independent_of(&server) =>
                {
                    self.end_pending(j, "moved");
                    self.current.remove(i);
                    self.current.insert(0, held(addr));
                    self.last_change = Some(ExternalAddrChange::Confirmed);
                    ConfirmOutcome::Accepted
                }
                Some(j) if self.pending[j].addr == addr => {
                    // A first server of unknown IP can never be told apart
                    // from a second one; keep one whose IP is known.
                    if self.pending[j].server.ip.is_none() {
                        self.pending[j].server = server;
                    }
                    ConfirmOutcome::Pending
                }
                Some(j) => {
                    self.end_pending(j, "replaced");
                    self.pending.push(new_move(addr));
                    ConfirmOutcome::Pending
                }
                None => {
                    self.pending.push(new_move(addr));
                    ConfirmOutcome::Pending
                }
            },
            None => {
                // Nothing to protect: the first confirmation is taken, as
                // at startup. A pending move ends with its transport's
                // address, so none can be left here.
                debug_assert!(
                    pending.is_none(),
                    "a pending move without a current address"
                );
                if let Some(j) = pending {
                    self.end_pending(j, "moved");
                }
                self.current.insert(0, held(addr));
                self.last_change = Some(ExternalAddrChange::Confirmed);
                ConfirmOutcome::Accepted
            }
        }
    }

    /// The swarm expired `address`. Returns whether the confirmed set changed.
    fn on_expired(&mut self, address: &Multiaddr) -> bool {
        let addr = without_peer_id(address);
        while let Some(j) = self.pending.iter().position(|p| p.addr == addr) {
            self.end_pending(j, "expired");
        }
        let Some(i) = self.current.iter().position(|h| h.addr == addr) else {
            return false;
        };
        let held = self.current.remove(i);
        if let Some(j) = self
            .pending
            .iter()
            .position(|p| p.transport == held.transport)
        {
            self.end_pending(j, "current_expired");
        }
        if self.current.is_empty() {
            self.kept_reported = false;
        }
        self.last_change = Some(ExternalAddrChange::Expired);
        true
    }

    fn end_pending(&mut self, j: usize, outcome: &'static str) {
        let ended = self.pending.remove(j);
        self.ended.push((ended.transport, ended.since, outcome));
    }

    /// Lines about moves to a new IP, as of `now`: one when a move starts,
    /// a warning once it has waited [`PENDING_WARN_AFTER`], one with its age
    /// when it ends. The swarm loop calls this after every change.
    pub(crate) fn pending_notices(&mut self, now: Instant) -> Vec<PendingNotice> {
        let age = |since: Instant| now.saturating_duration_since(since).as_secs();
        let mut notices: Vec<PendingNotice> = self
            .ended
            .drain(..)
            .filter_map(|(transport, since, outcome)| {
                since.map(|since| PendingNotice::Resolved {
                    transport,
                    secs: age(since),
                    outcome,
                })
            })
            .collect();
        for p in &mut self.pending {
            match p.since {
                None => {
                    p.since = Some(now);
                    notices.push(PendingNotice::Started {
                        transport: p.transport,
                    });
                }
                Some(since)
                    if !p.warned && now.saturating_duration_since(since) >= PENDING_WARN_AFTER =>
                {
                    p.warned = true;
                    notices.push(PendingNotice::Stale {
                        transport: p.transport,
                        secs: age(since),
                    });
                }
                _ => {}
            }
        }
        notices
    }

    pub(crate) fn snapshot(&self) -> ConfirmedExternalAddrs {
        ConfirmedExternalAddrs {
            addrs: self.current.iter().map(|h| h.addr.to_string()).collect(),
            last_change: self.last_change,
            autonat: AutonatSummary::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The node's routability rule, widened to the documentation ranges the
    /// tests use in place of real public addresses.
    fn routable(addr: &Multiaddr) -> bool {
        let documentation = addr.iter().any(|p| match p {
            Protocol::Ip4(ip) => ip.is_documentation(),
            _ => false,
        });
        documentation || crate::node::is_routable(addr)
    }

    fn tracker() -> ExternalAddrTracker {
        ExternalAddrTracker::new(Some(8336), Some(8336), routable)
    }

    fn ma(s: &str) -> Multiaddr {
        s.parse().unwrap()
    }

    fn with_peer(s: &str, server: PeerId) -> Multiaddr {
        ma(s).with(Protocol::P2p(server))
    }

    fn addrs(t: &ExternalAddrTracker) -> Vec<String> {
        t.snapshot().addrs
    }

    /// A server on an IP that no other test server has.
    fn any_server() -> ProbeServer {
        use std::sync::atomic::{AtomicU16, Ordering};
        static NEXT: AtomicU16 = AtomicU16::new(1);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let ip = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n);
        ProbeServer {
            peer: PeerId::random(),
            ip: Some(IpAddr::V6(ip)),
        }
    }

    fn server_on(ip: &str) -> ProbeServer {
        ProbeServer {
            peer: PeerId::random(),
            ip: Some(ip.parse().unwrap()),
        }
    }

    #[test]
    fn first_confirmation_is_accepted_without_its_peer_id() {
        let mut t = tracker();
        let server = any_server();
        let me = PeerId::random();
        assert_eq!(
            t.on_confirmed(&with_peer("/ip4/203.0.113.7/tcp/8336", me), server),
            ConfirmOutcome::Accepted
        );
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
        assert_eq!(
            t.snapshot().last_change,
            Some(ExternalAddrChange::Confirmed)
        );
    }

    #[test]
    fn reconfirming_the_current_address_changes_nothing() {
        let mut t = tracker();
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        let before = t.snapshot();
        assert_eq!(
            t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server()),
            ConfirmOutcome::Unchanged
        );
        assert_eq!(t.snapshot(), before);
    }

    /// A dynamic-IP change: the new address replaces the old once two
    /// distinct servers confirm it, and the old one is gone.
    #[test]
    fn a_new_ip_replaces_the_old_after_two_distinct_servers() {
        let mut t = tracker();
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        let first = any_server();
        assert_eq!(
            t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), first),
            ConfirmOutcome::Pending
        );
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
        // The same server again does not count twice.
        assert_eq!(
            t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), first),
            ConfirmOutcome::Pending
        );
        assert_eq!(
            t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), any_server()),
            ConfirmOutcome::Accepted
        );
        assert_eq!(addrs(&t), vec!["/ip4/198.51.100.9/tcp/8336"]);
    }

    /// Nodes behind one IP are one operator: however many confirm a new IP,
    /// it waits for a server on another IP.
    #[test]
    fn servers_sharing_an_ip_count_once() {
        let mut t = tracker();
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        for _ in 0..5 {
            assert_eq!(
                t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), server_on("192.0.2.44")),
                ConfirmOutcome::Pending
            );
        }
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
        assert_eq!(
            t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), server_on("192.0.2.45")),
            ConfirmOutcome::Accepted
        );
        assert_eq!(addrs(&t), vec!["/ip4/198.51.100.9/tcp/8336"]);
    }

    /// A move to a new IP logs once when it starts, warns once after 30
    /// minutes, and logs its age when it ends.
    #[test]
    fn a_pending_move_is_reported_warned_once_and_ended_with_its_age() {
        use PendingNotice::*;
        let t0 = Instant::now();
        let at = |m: u64| t0 + Duration::from_secs(60 * m);
        let mut t = tracker();
        let b = ma("/ip4/198.51.100.9/tcp/8336");
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        assert!(t.pending_notices(at(0)).is_empty());
        t.on_confirmed(&b, server_on("192.0.2.44"));
        assert_eq!(
            t.pending_notices(at(0)),
            vec![Started {
                transport: ExternalTransport::Tcp
            }]
        );
        t.on_confirmed(&b, server_on("192.0.2.44"));
        assert!(t.pending_notices(at(10)).is_empty());
        assert_eq!(
            t.pending_notices(at(31)),
            vec![Stale {
                transport: ExternalTransport::Tcp,
                secs: 31 * 60
            }]
        );
        assert!(t.pending_notices(at(40)).is_empty());
        assert_eq!(
            t.on_confirmed(&b, server_on("192.0.2.45")),
            ConfirmOutcome::Accepted
        );
        assert_eq!(
            t.pending_notices(at(45)),
            vec![Resolved {
                transport: ExternalTransport::Tcp,
                secs: 45 * 60,
                outcome: "moved"
            }]
        );
        assert!(t.pending_notices(at(50)).is_empty());
    }

    /// A server of unknown IP never counts as the second one, and gives its
    /// pending slot to a server whose IP is known.
    #[test]
    fn a_server_of_unknown_ip_does_not_count_twice() {
        let mut t = tracker();
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        let unknown = || ProbeServer {
            peer: PeerId::random(),
            ip: None,
        };
        let b = ma("/ip4/198.51.100.9/tcp/8336");
        assert_eq!(t.on_confirmed(&b, unknown()), ConfirmOutcome::Pending);
        assert_eq!(t.on_confirmed(&b, unknown()), ConfirmOutcome::Pending);
        assert_eq!(
            t.on_confirmed(&b, server_on("192.0.2.44")),
            ConfirmOutcome::Pending
        );
        assert_eq!(t.on_confirmed(&b, unknown()), ConfirmOutcome::Pending);
        assert_eq!(
            t.on_confirmed(&b, server_on("192.0.2.45")),
            ConfirmOutcome::Accepted
        );
    }

    /// One server's claim is dropped once another server still reaches us
    /// on the current address.
    #[test]
    fn a_current_reconfirmation_discards_a_pending_ip() {
        let mut t = tracker();
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), any_server());
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        assert_eq!(
            t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), any_server()),
            ConfirmOutcome::Pending
        );
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
    }

    #[test]
    fn transports_are_tracked_separately_newest_first() {
        let mut t = tracker();
        t.on_confirmed(&ma("/ip4/203.0.113.7/udp/8336/quic-v1"), any_server());
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        assert_eq!(
            addrs(&t),
            vec![
                "/ip4/203.0.113.7/tcp/8336",
                "/ip4/203.0.113.7/udp/8336/quic-v1"
            ]
        );
        // Replacing the QUIC address moves it to the front and keeps TCP.
        t.on_confirmed(&ma("/ip4/198.51.100.9/udp/8336/quic-v1"), any_server());
        t.on_confirmed(&ma("/ip4/198.51.100.9/udp/8336/quic-v1"), any_server());
        assert_eq!(
            addrs(&t),
            vec![
                "/ip4/198.51.100.9/udp/8336/quic-v1",
                "/ip4/203.0.113.7/tcp/8336"
            ]
        );
    }

    #[test]
    fn expiry_removes_the_address_and_reports_it() {
        let mut t = tracker();
        let server = any_server();
        t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/8336"), any_server());
        assert!(!t.on_expired(&ma("/ip4/198.51.100.9/tcp/8336")));
        assert!(t.on_expired(&with_peer("/ip4/203.0.113.7/tcp/8336", server.peer)));
        assert!(addrs(&t).is_empty());
        assert_eq!(t.snapshot().last_change, Some(ExternalAddrChange::Expired));
        // With nothing established, the next confirmation needs one server.
        assert_eq!(
            t.on_confirmed(&ma("/ip4/198.51.100.9/tcp/8336"), server),
            ConfirmOutcome::Accepted
        );
    }

    #[test]
    fn rejects_other_ports_and_transports() {
        let mut t = ExternalAddrTracker::new(Some(8336), None, routable);
        let server = any_server();
        assert_eq!(
            t.on_confirmed(&ma("/ip4/203.0.113.7/tcp/40123"), server),
            ConfirmOutcome::Rejected("port")
        );
        assert_eq!(
            t.on_confirmed(&ma("/ip4/203.0.113.7/udp/8336/quic-v1"), server),
            ConfirmOutcome::Rejected("port")
        );
        assert_eq!(
            t.on_confirmed(&ma("/ip4/203.0.113.7/udp/8336"), server),
            ConfirmOutcome::Rejected("transport")
        );
        assert!(addrs(&t).is_empty());
    }

    #[test]
    fn rejects_addresses_peers_cannot_route_to() {
        let mut t = tracker();
        for addr in [
            "/ip4/0.0.0.0/tcp/8336",
            "/ip4/127.0.0.1/tcp/8336",
            "/ip4/10.1.2.3/tcp/8336",
            "/ip4/192.168.1.20/udp/8336/quic-v1",
        ] {
            assert_eq!(
                t.on_confirmed(&ma(addr), any_server()),
                ConfirmOutcome::Rejected("not_routable"),
                "{addr}"
            );
        }
        assert!(addrs(&t).is_empty());
        assert_eq!(t.snapshot().last_change, None);
    }

    fn public() -> NatStatus {
        NatStatus::Public(ma("/ip4/203.0.113.7/tcp/8336"))
    }

    fn minutes(t0: Instant, m: u64) -> Instant {
        t0 + Duration::from_secs(60 * m)
    }

    fn confirm(
        t: &mut ExternalAddrTracker,
        addr: &Multiaddr,
        nat: &NatStatus,
        at: Instant,
    ) -> Applied {
        t.apply(ExternalAddrEvent::Confirmed(addr, any_server()), nat, at)
    }

    /// `n` probes that found the node unreachable, from `at` on, spaced so
    /// that each counts.
    fn unreachable(t: &mut ExternalAddrTracker, n: u32, nat: &NatStatus, at: Instant) {
        for k in 0..n {
            let when = at + MISS_SPACING * k;
            assert_eq!(
                t.apply(ExternalAddrEvent::Failed(ProbeMiss::Unreachable), nat, when),
                Applied::Nothing
            );
        }
    }

    const WINDOW: u64 = KEEP_UNCONFIRMED.as_secs() / 60;

    /// Servers report dial-backs they refused themselves as failed dials, so
    /// AutoNAT holds a reachable node private: that keeps every address,
    /// pending moves included, and reports each address once.
    #[test]
    fn a_private_status_keeps_every_address_and_reports_it_once() {
        let t0 = Instant::now();
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        let b = ma("/ip4/198.51.100.9/tcp/8336");
        let q = ma("/ip4/203.0.113.7/udp/8336/quic-v1");
        confirm(&mut t, &a, &public(), t0);
        confirm(&mut t, &q, &public(), minutes(t0, 1));
        confirm(&mut t, &b, &public(), minutes(t0, 2));
        assert_eq!(t.pending.len(), 1);
        assert!(t.hold_notices().is_empty());
        unreachable(&mut t, 1, &NatStatus::Private, minutes(t0, 5));
        assert!(!t.expire_unconfirmed(minutes(t0, 5)));
        assert_eq!(
            addrs(&t),
            vec![
                "/ip4/203.0.113.7/udp/8336/quic-v1",
                "/ip4/203.0.113.7/tcp/8336"
            ]
        );
        assert_eq!(t.pending.len(), 1);
        assert_eq!(
            t.snapshot().last_change,
            Some(ExternalAddrChange::Confirmed)
        );
        assert_eq!(
            t.hold_notices(),
            vec![
                HoldNotice::Kept {
                    transport: ExternalTransport::Quic,
                    addr: q.to_string(),
                    confirmed_secs: 4 * 60
                },
                HoldNotice::Kept {
                    transport: ExternalTransport::Tcp,
                    addr: a.to_string(),
                    confirmed_secs: 5 * 60
                },
            ]
        );
        // Further private outcomes and flips do not repeat the line.
        t.apply(
            ExternalAddrEvent::StatusChanged,
            &NatStatus::Private,
            minutes(t0, 6),
        );
        confirm(&mut t, &a, &NatStatus::Private, minutes(t0, 7));
        unreachable(&mut t, 3, &NatStatus::Private, minutes(t0, 8));
        assert!(t.hold_notices().is_empty());
        // After a public spell, the next private run reports again.
        t.apply(ExternalAddrEvent::StatusChanged, &public(), minutes(t0, 9));
        t.apply(
            ExternalAddrEvent::StatusChanged,
            &NatStatus::Private,
            minutes(t0, 10),
        );
        assert_eq!(t.hold_notices().len(), 2);
    }

    /// A dial-back is a confirmation whatever AutoNAT's status.
    #[test]
    fn a_dial_back_counts_whatever_autonats_status() {
        let t0 = Instant::now();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        for nat in [NatStatus::Private, NatStatus::Unknown, public()] {
            let mut t = tracker();
            assert_eq!(
                confirm(&mut t, &a, &nat, t0),
                Applied::Confirm(ConfirmOutcome::Accepted),
                "{nat:?}"
            );
            assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
        }
    }

    /// An address goes, with one line, only once the window has passed and
    /// enough probes found the node unreachable; inconclusive probes do not
    /// count.
    #[test]
    fn an_address_goes_after_the_window_and_enough_unreachable_probes() {
        let t0 = Instant::now();
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        confirm(&mut t, &a, &NatStatus::Unknown, t0);
        for _ in 0..50 {
            t.apply(
                ExternalAddrEvent::Failed(ProbeMiss::Inconclusive),
                &NatStatus::Private,
                minutes(t0, 1),
            );
        }
        unreachable(
            &mut t,
            DROP_AFTER_UNREACHABLE - 1,
            &NatStatus::Private,
            minutes(t0, 1),
        );
        t.hold_notices();
        assert!(!t.expire_unconfirmed(minutes(t0, 10 * WINDOW)));
        unreachable(&mut t, 1, &NatStatus::Private, minutes(t0, 10 * WINDOW));
        assert!(!t.expire_unconfirmed(minutes(t0, WINDOW - 1)));
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
        assert!(t.expire_unconfirmed(minutes(t0, WINDOW)));
        assert!(addrs(&t).is_empty());
        assert_eq!(t.snapshot().last_change, Some(ExternalAddrChange::Stale));
        assert_eq!(
            t.hold_notices(),
            vec![HoldNotice::Dropped {
                transport: ExternalTransport::Tcp,
                addr: a.to_string(),
                unconfirmed_secs: WINDOW * 60,
                unreachable_probes: DROP_AFTER_UNREACHABLE,
            }]
        );
        assert!(!t.expire_unconfirmed(minutes(t0, WINDOW + 5)));
        assert!(t.hold_notices().is_empty());
        // The next dial-back brings it back, needing one server again.
        let at = minutes(t0, WINDOW + 10);
        assert_eq!(
            confirm(&mut t, &a, &NatStatus::Private, at),
            Applied::Confirm(ConfirmOutcome::Accepted)
        );
        assert_eq!(t.hold_notices().len(), 1);
    }

    /// A port forward that breaks while AutoNAT holds the node public: the
    /// dial-backs time out, which leaves the status public, and the address
    /// still goes. Without such probes a public node keeps it.
    #[test]
    fn a_public_node_loses_an_address_its_probes_cannot_reach() {
        let t0 = Instant::now();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        let mut kept = tracker();
        confirm(&mut kept, &a, &public(), t0);
        for _ in 0..50 {
            kept.apply(
                ExternalAddrEvent::Failed(ProbeMiss::Inconclusive),
                &public(),
                minutes(t0, 1),
            );
        }
        assert!(!kept.expire_unconfirmed(minutes(t0, 10 * WINDOW)));
        assert_eq!(addrs(&kept), vec!["/ip4/203.0.113.7/tcp/8336"]);

        let mut lost = tracker();
        confirm(&mut lost, &a, &public(), t0);
        unreachable(
            &mut lost,
            DROP_AFTER_UNREACHABLE,
            &public(),
            minutes(t0, 20),
        );
        assert!(!lost.expire_unconfirmed(minutes(t0, WINDOW - 1)));
        assert!(lost.expire_unconfirmed(minutes(t0, WINDOW)));
        assert!(addrs(&lost).is_empty());
        assert!(matches!(
            lost.hold_notices()[..],
            [HoldNotice::Dropped { .. }]
        ));
    }

    /// A few minutes of lost uplink bring a burst of timeouts, retried at
    /// once: they count as one miss per spacing and cannot drop a reachable
    /// node's address.
    #[test]
    fn a_burst_of_timeouts_does_not_drop_an_address() {
        let t0 = Instant::now();
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        confirm(&mut t, &a, &public(), t0);
        // Six minutes of timeouts, one every 30 s, 50 minutes after the
        // confirmation.
        let burst = minutes(t0, 50);
        for k in 0..12u32 {
            t.apply(
                ExternalAddrEvent::Failed(ProbeMiss::Unreachable),
                &public(),
                burst + Duration::from_secs(30) * k,
            );
        }
        assert!(t.current[0].unreachable_probes <= 4);
        for at in [minutes(t0, WINDOW), minutes(t0, 2 * WINDOW)] {
            assert!(!t.expire_unconfirmed(at));
        }
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
    }

    /// Behind a NAT whose forward of the listen port broke, servers still
    /// reach the node on a port the NAT maps: each such dial-back means the
    /// listen port failed, so the address on it goes in time.
    #[test]
    fn dial_backs_on_another_port_count_against_the_listen_port_address() {
        let t0 = Instant::now();
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        let mapped = ma("/ip4/203.0.113.7/tcp/40123");
        let quic = ma("/ip4/203.0.113.7/udp/8336/quic-v1");
        confirm(&mut t, &a, &public(), t0);
        confirm(&mut t, &quic, &public(), t0);
        for k in 0..DROP_AFTER_UNREACHABLE {
            let at = minutes(t0, 5) + MISS_SPACING * k;
            assert_eq!(
                t.apply(
                    ExternalAddrEvent::Confirmed(&mapped, any_server()),
                    &public(),
                    at
                ),
                Applied::Confirm(ConfirmOutcome::Rejected("port"))
            );
        }
        assert!(!t.expire_unconfirmed(minutes(t0, WINDOW - 1)));
        assert!(t.expire_unconfirmed(minutes(t0, WINDOW)));
        // Only the TCP address: the QUIC one was not dialed first.
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/udp/8336/quic-v1"]);
    }

    /// An address that aged while AutoNAT held the node public gets its
    /// hour from the flip to private, and is reported kept, not dropped.
    #[test]
    fn the_window_starts_when_the_node_leaves_public() {
        let t0 = Instant::now();
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        confirm(&mut t, &a, &public(), t0);
        let flip = minutes(t0, 2 * WINDOW);
        unreachable(&mut t, DROP_AFTER_UNREACHABLE, &NatStatus::Private, flip);
        assert!(!t.expire_unconfirmed(flip));
        assert_eq!(
            t.hold_notices(),
            vec![HoldNotice::Kept {
                transport: ExternalTransport::Tcp,
                addr: a.to_string(),
                confirmed_secs: 2 * WINDOW * 60,
            }]
        );
        assert!(!t.expire_unconfirmed(minutes(t0, 3 * WINDOW - 1)));
        assert!(t.expire_unconfirmed(minutes(t0, 3 * WINDOW)));
        assert!(
            matches!(t.hold_notices()[..], [HoldNotice::Dropped { unconfirmed_secs, .. }] if unconfirmed_secs == 3 * WINDOW * 60)
        );
    }

    /// An entry already past its window when AutoNAT turns private is
    /// dropped, never reported kept.
    #[test]
    fn an_address_past_its_window_is_not_reported_kept() {
        let t0 = Instant::now();
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        confirm(&mut t, &a, &NatStatus::Unknown, t0);
        unreachable(
            &mut t,
            DROP_AFTER_UNREACHABLE,
            &NatStatus::Unknown,
            minutes(t0, 1),
        );
        unreachable(&mut t, 1, &NatStatus::Private, minutes(t0, WINDOW));
        assert!(t.hold_notices().is_empty());
        assert!(t.expire_unconfirmed(minutes(t0, WINDOW)));
        assert!(matches!(t.hold_notices()[..], [HoldNotice::Dropped { .. }]));
    }

    /// The sparse dial-backs a reachable node gets while held private keep
    /// its address: each restarts the window and the count.
    #[test]
    fn a_dial_back_restarts_the_window_and_the_count() {
        let t0 = Instant::now();
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        confirm(&mut t, &a, &public(), t0);
        for k in 1..=5 {
            let at = minutes(t0, k * WINDOW);
            unreachable(&mut t, DROP_AFTER_UNREACHABLE - 1, &NatStatus::Private, at);
            assert!(!t.expire_unconfirmed(at));
            assert_eq!(
                confirm(&mut t, &a, &NatStatus::Private, at),
                Applied::Confirm(ConfirmOutcome::Unchanged)
            );
        }
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
    }

    /// Only the stale transport goes; one confirmed since stays.
    #[test]
    fn the_window_is_kept_per_transport() {
        let t0 = Instant::now();
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        let q = ma("/ip4/203.0.113.7/udp/8336/quic-v1");
        confirm(&mut t, &a, &NatStatus::Unknown, t0);
        unreachable(
            &mut t,
            DROP_AFTER_UNREACHABLE,
            &NatStatus::Unknown,
            minutes(t0, 1),
        );
        confirm(&mut t, &q, &NatStatus::Unknown, minutes(t0, 30));
        assert!(t.expire_unconfirmed(minutes(t0, WINDOW)));
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/udp/8336/quic-v1"]);
    }

    /// A dropped address takes its transport's pending move with it, so the
    /// move's single server never stands in for a second one later.
    #[test]
    fn dropping_an_address_ends_its_pending_move() {
        let t0 = Instant::now();
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        let b = ma("/ip4/198.51.100.9/tcp/8336");
        confirm(&mut t, &a, &NatStatus::Unknown, t0);
        assert_eq!(
            t.apply(
                ExternalAddrEvent::Confirmed(&b, server_on("192.0.2.44")),
                &NatStatus::Unknown,
                t0
            ),
            Applied::Confirm(ConfirmOutcome::Pending)
        );
        assert_eq!(
            t.pending_notices(t0),
            vec![PendingNotice::Started {
                transport: ExternalTransport::Tcp
            }]
        );
        unreachable(
            &mut t,
            DROP_AFTER_UNREACHABLE,
            &NatStatus::Unknown,
            minutes(t0, 1),
        );
        assert!(t.expire_unconfirmed(minutes(t0, WINDOW)));
        assert!(t.pending.is_empty());
        assert_eq!(
            t.pending_notices(minutes(t0, WINDOW)),
            vec![PendingNotice::Resolved {
                transport: ExternalTransport::Tcp,
                secs: WINDOW * 60,
                outcome: "current_dropped",
            }]
        );
    }

    /// A new IP still needs two independent servers while held private, and
    /// then replaces the old address at once.
    #[test]
    fn a_new_ip_moves_while_private_after_two_distinct_servers() {
        let t0 = Instant::now();
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        let b = ma("/ip4/198.51.100.9/tcp/8336");
        confirm(&mut t, &a, &public(), t0);
        let private = NatStatus::Private;
        assert_eq!(
            t.apply(
                ExternalAddrEvent::Confirmed(&b, server_on("192.0.2.44")),
                &private,
                t0
            ),
            Applied::Confirm(ConfirmOutcome::Pending)
        );
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
        assert_eq!(
            t.apply(
                ExternalAddrEvent::Confirmed(&b, server_on("192.0.2.45")),
                &private,
                t0
            ),
            Applied::Confirm(ConfirmOutcome::Accepted)
        );
        assert_eq!(addrs(&t), vec!["/ip4/198.51.100.9/tcp/8336"]);
    }

    #[test]
    fn expiry_clears_pending_entries() {
        let t0 = Instant::now();
        let mut t = tracker();
        let a = ma("/ip4/203.0.113.7/tcp/8336");
        let b = ma("/ip4/198.51.100.9/tcp/8336");
        confirm(&mut t, &a, &public(), t0);
        let first = confirm(&mut t, &b, &public(), t0);
        assert_eq!(first, Applied::Confirm(ConfirmOutcome::Pending));
        assert!(!first.changed());
        assert_eq!(t.pending.len(), 1);
        // Expiry of the pending address drops it; A stays.
        assert_eq!(
            t.apply(ExternalAddrEvent::Expired(&b), &public(), t0),
            Applied::Expired(false)
        );
        assert!(t.pending.is_empty());
        assert_eq!(addrs(&t), vec!["/ip4/203.0.113.7/tcp/8336"]);
        // So B needs two fresh servers again; expiry of A ends that move.
        assert_eq!(
            confirm(&mut t, &b, &public(), t0),
            Applied::Confirm(ConfirmOutcome::Pending)
        );
        let expired = t.apply(ExternalAddrEvent::Expired(&a), &public(), t0);
        assert_eq!(expired, Applied::Expired(true));
        assert!(expired.changed());
        assert!(addrs(&t).is_empty());
        assert!(t.pending.is_empty());
    }

    #[test]
    fn transport_of_reads_tcp_and_quic() {
        assert_eq!(
            transport_of("/ip4/0.0.0.0/tcp/8336"),
            Some(ExternalTransport::Tcp)
        );
        assert_eq!(
            transport_of("/ip4/0.0.0.0/udp/8336/quic-v1"),
            Some(ExternalTransport::Quic)
        );
        assert_eq!(transport_of("/ip4/0.0.0.0/udp/8336"), None);
        assert_eq!(transport_of("not a multiaddr"), None);
    }
}
