//! Whether peers can dial this node, judged from its own view: its p2p
//! listeners, AutoNAT's status, confirmed addresses and current run of probes
//! without a dial-back, and the addresses its PeerInfo announces.
//!
//! The node judges this for its health conditions and `qclient node doctor`
//! turns the same assessment into advice, so one rule gives both answers. It
//! gives one state per address family and transport. Pure logic, no I/O.

use std::net::{IpAddr, Ipv4Addr};

use quil_types::proto::node::NodeReachability;
use serde::Serialize;

/// What kind of network an IP address belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpClass {
    /// Globally routable (documentation ranges included).
    Public,
    /// A private network behind a NAT: RFC 1918 IPv4, unique-local IPv6.
    Private,
    /// Shared address space for carrier-grade NAT, 100.64.0.0/10 (RFC
    /// 6598): the ISP's NAT, which the operator cannot forward ports on.
    Shared,
    /// Loopback, link-local or unspecified: this host or link only.
    Local,
}

pub fn ip_class(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => ipv4_class(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => ipv4_class(v4),
            None if v6.is_loopback() || v6.is_unspecified() || v6.is_unicast_link_local() => {
                IpClass::Local
            }
            None if v6.is_unique_local() => IpClass::Private,
            None => IpClass::Public,
        },
    }
}

fn ipv4_class(ip: Ipv4Addr) -> IpClass {
    // `Ipv4Addr::is_shared` is not stable.
    let shared = ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 0x40;
    if ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() {
        IpClass::Local
    } else if ip.is_private() {
        IpClass::Private
    } else if shared {
        IpClass::Shared
    } else {
        IpClass::Public
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    fn of(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Family::Ipv4,
            IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() => Family::Ipv4,
            IpAddr::V6(_) => Family::Ipv6,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Family::Ipv4 => "IPv4",
            Family::Ipv6 => "IPv6",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Quic,
}

impl Transport {
    pub fn label(self) -> &'static str {
        match self {
            Transport::Tcp => "TCP",
            Transport::Quic => "QUIC",
        }
    }

    /// The IP protocol to open or forward.
    pub fn protocol(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp",
            Transport::Quic => "udp",
        }
    }
}

/// The IP, transport and port of a TCP or QUIC multiaddr.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub transport: Transport,
    pub port: u16,
}

impl Endpoint {
    pub fn parse(multiaddr: &str) -> Option<Self> {
        let parts: Vec<&str> = multiaddr.trim_matches('/').split('/').collect();
        let ip = match parts.as_slice() {
            ["ip4", ip, ..] => IpAddr::V4(ip.parse().ok()?),
            ["ip6", ip, ..] => IpAddr::V6(ip.parse().ok()?),
            _ => return None,
        };
        let (transport, port) = match &parts[2..] {
            ["tcp", port, ..] => (Transport::Tcp, port),
            ["udp", port, "quic-v1" | "quic", ..] => (Transport::Quic, port),
            _ => return None,
        };
        Some(Endpoint {
            ip,
            transport,
            port: port.parse().ok()?,
        })
    }

    pub fn family(&self) -> Family {
        Family::of(self.ip)
    }

    pub fn host_port(&self) -> String {
        match self.ip {
            IpAddr::V4(ip) => format!("{ip}:{}", self.port),
            IpAddr::V6(ip) => format!("[{ip}]:{}", self.port),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Reachable,
    NotReachable,
    Unknown,
}

impl Verdict {
    pub fn exit_code(self) -> i32 {
        match self {
            Verdict::Reachable => 0,
            Verdict::NotReachable => 1,
            Verdict::Unknown => 2,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Verdict::Reachable => "reachable",
            Verdict::NotReachable => "not reachable",
            Verdict::Unknown => "unknown",
        }
    }
}

/// The state of one transport of one address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckState {
    Reachable,
    NotReachable,
    Unknown,
    /// The node has no listener of this family and transport.
    NoListener,
}

impl CheckState {
    pub fn label(self) -> &'static str {
        match self {
            CheckState::Reachable => "reachable",
            CheckState::NotReachable => "not reachable",
            CheckState::Unknown => "unknown",
            CheckState::NoListener => "no listener",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    pub transport: Transport,
    /// The listen port; `None` without a listener.
    pub port: Option<u16>,
    pub state: CheckState,
    /// What the state rests on.
    pub evidence: String,
}

/// The kind of address this host has in a family, which decides the advice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostClass {
    Public,
    /// Behind a router's NAT.
    Private,
    /// Carrier-grade NAT, 100.64.0.0/10.
    Cgnat,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProbeRun {
    pub class: String,
    pub probes: u32,
    pub failing_secs: u64,
    pub unreachable: bool,
}

const TRANSPORTS: [Transport; 2] = [Transport::Tcp, Transport::Quic];

/// One address family's checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyChecks {
    pub family: Family,
    /// This host's address that decides the advice, and its class.
    pub host: Option<(IpAddr, HostClass)>,
    pub checks: Vec<Check>,
}

/// What `report` establishes about this node's reachability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assessment {
    pub verdict: Verdict,
    pub families: Vec<FamilyChecks>,
    pub probe_failure: Option<ProbeRun>,
    pub ipv6_note: Option<Ipv6Note>,
}

/// The verdict of `report`, each family's checks and the IPv6 note.
pub fn assess(report: &NodeReachability) -> Assessment {
    let listeners: Vec<Endpoint> = report
        .listen_multiaddrs
        .iter()
        .filter_map(|a| Endpoint::parse(a))
        .collect();
    let confirmed: Vec<Endpoint> = report
        .confirmed_multiaddrs
        .iter()
        .filter_map(|a| Endpoint::parse(a))
        .collect();
    let announced: Vec<Endpoint> = report
        .announced_pubsub_multiaddrs
        .iter()
        .filter_map(|a| Endpoint::parse(a))
        .collect();
    let run = report.probe_failure.as_ref().map(|run| ProbeRun {
        class: run.class.clone(),
        probes: run.probes,
        failing_secs: run.failing_secs,
        unreachable: run.unreachable,
    });
    // Families with a listener beyond this host, or an address peers see.
    let seen = |family: Family| {
        listeners
            .iter()
            .any(|e| e.family() == family && ip_class(e.ip) != IpClass::Local)
            || confirmed
                .iter()
                .chain(&announced)
                .any(|e| e.family() == family)
    };
    let families: Vec<Family> = [Family::Ipv4, Family::Ipv6]
        .into_iter()
        .filter(|f| *f == Family::Ipv4 || seen(*f))
        .collect();
    // AutoNAT's status and failures do not name a family: they tell about
    // a family only while it is the only one listened on.
    let attributable = families.iter().filter(|f| seen(**f)).count() <= 1;

    let mut checked = Vec::new();
    for family in families {
        let host = host_address(&listeners, family);
        let mut checks = Vec::new();
        for transport in TRANSPORTS {
            let port = listeners
                .iter()
                .find(|e| e.family() == family && e.transport == transport)
                .map(|e| e.port);
            let (state, evidence) = match port {
                None => (
                    CheckState::NoListener,
                    format!(
                        "the node has no {} {} listener",
                        family.label(),
                        transport.label()
                    ),
                ),
                Some(_) => check(
                    family,
                    transport,
                    &confirmed,
                    host,
                    report,
                    run.as_ref(),
                    attributable,
                ),
            };
            checks.push(Check {
                transport,
                port,
                state,
                evidence,
            });
        }
        checked.push(FamilyChecks {
            family,
            host,
            checks,
        });
    }

    let states = || {
        checked
            .iter()
            .flat_map(|r| r.checks.iter().map(|c| c.state))
    };
    let verdict = if states().any(|s| s == CheckState::Reachable) {
        Verdict::Reachable
    } else if states().any(|s| s == CheckState::NotReachable) {
        Verdict::NotReachable
    } else {
        Verdict::Unknown
    };
    let ipv6_note = ipv6_note(
        &listeners,
        &confirmed,
        &announced,
        report.announced,
        verdict,
    );
    Assessment {
        verdict,
        families: checked,
        probe_failure: run,
        ipv6_note,
    }
}

/// What this node binds and publishes on IPv6, when that decides whether
/// IPv6 carries dials to it. It states what the node does now, so it holds
/// for any build: a node that binds and publishes IPv6 gets its checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ipv6Note {
    /// It binds no address peers could dial and publishes none, while the
    /// node is not known reachable.
    NoneBound,
    /// It binds `bound` but publishes no IPv6 address.
    NotPublished { bound: String },
    /// AutoNAT confirmed only IPv6 addresses.
    ConfirmedOnly,
}

impl Ipv6Note {
    pub fn text(&self) -> String {
        match self {
            Ipv6Note::NoneBound => {
                "IPv6: this node binds no address peers could dial and publishes none.".to_string()
            }
            Ipv6Note::NotPublished { bound } => format!(
                "IPv6: this node binds {bound} but publishes no IPv6 address, so peers do not \
                 learn it."
            ),
            Ipv6Note::ConfirmedOnly => {
                "AutoNAT confirmed IPv6 only, so peers with IPv4 alone may not reach this node."
                    .to_string()
            }
        }
    }
}

fn ipv6_note(
    listeners: &[Endpoint],
    confirmed: &[Endpoint],
    announced: &[Endpoint],
    has_published: bool,
    verdict: Verdict,
) -> Option<Ipv6Note> {
    let is_v6 = |e: &&Endpoint| e.family() == Family::Ipv6;
    let bound = listeners
        .iter()
        .filter(is_v6)
        .find(|e| ip_class(e.ip) != IpClass::Local);
    let published = announced.iter().any(|e| e.family() == Family::Ipv6);
    match bound {
        None if !published && verdict != Verdict::Reachable => Some(Ipv6Note::NoneBound),
        Some(e) if !published && has_published => Some(Ipv6Note::NotPublished {
            bound: e.host_port(),
        }),
        _ if confirmed.iter().any(|e| e.family() == Family::Ipv6)
            && confirmed.iter().all(|e| e.family() == Family::Ipv6) =>
        {
            Some(Ipv6Note::ConfirmedOnly)
        }
        _ => None,
    }
}

/// The address of `family` that decides the advice: a public one first,
/// then a private one (a VPN's 100.64.0.0/10 address beside a LAN address
/// does not make the host CGNAT), then a carrier-grade NAT one.
fn host_address(listeners: &[Endpoint], family: Family) -> Option<(IpAddr, HostClass)> {
    let of_class = |class: IpClass| {
        listeners
            .iter()
            .find(|e| e.family() == family && ip_class(e.ip) == class)
            .map(|e| e.ip)
    };
    of_class(IpClass::Public)
        .map(|ip| (ip, HostClass::Public))
        .or_else(|| of_class(IpClass::Private).map(|ip| (ip, HostClass::Private)))
        .or_else(|| of_class(IpClass::Shared).map(|ip| (ip, HostClass::Cgnat)))
}

/// The state of a listened-on transport and what it rests on.
fn check(
    family: Family,
    transport: Transport,
    confirmed: &[Endpoint],
    host: Option<(IpAddr, HostClass)>,
    report: &NodeReachability,
    run: Option<&ProbeRun>,
    attributable: bool,
) -> (CheckState, String) {
    if let Some(addr) = confirmed
        .iter()
        .find(|e| e.family() == family && e.transport == transport)
    {
        return (
            CheckState::Reachable,
            format!(
                "AutoNAT servers dialed this node back at {}",
                addr.host_port()
            ),
        );
    }
    if let Some(other) = confirmed.first() {
        return (
            CheckState::Unknown,
            format!(
                "AutoNAT confirmed {} {} only; a probe confirms one address",
                other.family().label(),
                other.transport.label()
            ),
        );
    }
    if let Some((ip, HostClass::Cgnat)) = host {
        return (
            CheckState::NotReachable,
            format!("this host's address {ip} is behind carrier-grade NAT"),
        );
    }
    if !attributable {
        return (
            CheckState::Unknown,
            "AutoNAT has confirmed no address, and its results do not name the address family"
                .to_string(),
        );
    }
    if let Some(run) = run.filter(|run| run.unreachable) {
        return (
            CheckState::NotReachable,
            format!(
                "AutoNAT servers on 2 or more IPs could not dial this node back ({})",
                run_text(run)
            ),
        );
    }
    if report.nat_status == "private" {
        return (
            CheckState::NotReachable,
            "AutoNAT holds this node private and has confirmed no address".to_string(),
        );
    }
    let evidence = match run {
        Some(run) => format!("{}: {}", run_text(run), class_meaning(&run.class)),
        None if report.nat_status == "public" => {
            "AutoNAT holds this node public but has confirmed no usable address".to_string()
        }
        None => "AutoNAT has finished no probe yet".to_string(),
    };
    (CheckState::Unknown, evidence)
}

/// `14 probes in a row without a dial-back over 32 min, mostly dial_error`.
pub fn run_text(run: &ProbeRun) -> String {
    format!(
        "{} probes in a row without a dial-back over {}, mostly {}",
        run.probes,
        duration_text(run.failing_secs),
        run.class
    )
}

/// What a failure class that does not settle reachability means.
fn class_meaning(class: &str) -> &'static str {
    match class {
        "dial_error" | "timeout" => "waiting for servers on other IPs",
        "dial_refused" => "servers declined to dial back, at their own limits",
        "no_server" | "no_addresses" => "no probe could be sent yet",
        _ => "requests fail before any dial-back; report this if it persists",
    }
}

fn duration_text(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min", secs / 60),
        _ => format!("{} h {} min", secs / 3600, secs % 3600 / 60),
    }
}
