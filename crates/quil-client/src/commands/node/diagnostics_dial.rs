//! `qclient node diagnostics dial` — whether a node's libp2p listener
//! answers, tested from wherever qclient runs.
//!
//! Dials one multiaddr as a throwaway Ed25519 identity over the stack the
//! network's nodes listen with (`quil_p2p::node`: PQNoise sntrup761 and
//! yamux over TCP, QUIC v1 whose TLS 1.3 negotiates sntrup761), checks the
//! peer ID the handshake proves, and prints what the peer reports over
//! identify, plus one ping round trip. It reads no key and asks no local
//! node.

use std::fmt::Write as _;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use clap::Args;
use futures::StreamExt;
use libp2p::core::muxing::StreamMuxerBox;
use libp2p::core::transport::Boxed;
use libp2p::core::upgrade::Version;
use libp2p::multiaddr::Protocol;
use libp2p::swarm::{DialError, NetworkBehaviour, SwarmEvent};
use libp2p::{identify, ping, Multiaddr, PeerId, Swarm, Transport};
use libp2p_identity::Keypair;
use quil_p2p::pqnoise_transport::PqNoiseConfig;

/// The identify protocol version mainnet nodes announce (`quil_p2p::node`
/// formats `/quilibrium/2.0.2/<network>`).
const PROTOCOL_VERSION: &str = "/quilibrium/2.0.2/0";

/// Peer-supplied text longer than this is cut.
const MAX_TEXT_CHARS: usize = 200;

/// Width of the label column of the output.
const LABEL_WIDTH: usize = 11;

#[derive(Debug, Args)]
pub struct DialArgs {
    /// The address to dial: /ip4, /ip6, /dns, /dns4 or /dns6, then
    /// /tcp/<port> or /udp/<port>/quic-v1, optionally ending in
    /// /p2p/<peer-id>, e.g. /ip4/198.51.100.7/tcp/8336.
    pub multiaddr: String,
    /// The peer ID (base58) the address should answer as; a trailing
    /// /p2p/<peer-id> names it too.
    #[arg(long)]
    pub peer: Option<String>,
    /// Seconds to wait for the connection, and again for identify and ping.
    #[arg(long, value_name = "SECS", default_value_t = 10, value_parser = clap::value_parser!(u64).range(1..=300))]
    pub timeout: u64,
}

pub async fn run(args: &DialArgs) -> anyhow::Result<()> {
    let target = parse_target(&args.multiaddr, args.peer.as_deref())?;
    let addr = resolve(&target).await?;
    let report = dial(&target, addr, Duration::from_secs(args.timeout))
        .await
        .map_err(|failure| anyhow!("{failure}"))?;
    print!("{}", render(&report));
    Ok(())
}

/// The transport an address names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Carrier {
    Tcp,
    Quic,
}

impl Carrier {
    fn stack(self) -> &'static str {
        match self {
            Carrier::Tcp => "TCP (PQNoise sntrup761, yamux)",
            Carrier::Quic => "QUIC v1 (TLS 1.3 with sntrup761)",
        }
    }

    fn endpoint(self, addr: SocketAddr) -> String {
        match self {
            Carrier::Tcp => addr.to_string(),
            Carrier::Quic => format!("{addr} (UDP)"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    Any,
    V4,
    V6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Host {
    Ip(IpAddr),
    Dns { name: String, family: Family },
}

/// The peer ID an address should answer as, and where it was named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Expected {
    peer: PeerId,
    source: &'static str,
}

/// A parsed `dial` address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    host: Host,
    port: u16,
    carrier: Carrier,
    expected: Option<Expected>,
}

pub(crate) fn parse_target(multiaddr: &str, peer: Option<&str>) -> anyhow::Result<Target> {
    let text = printable(multiaddr.trim());
    let addr = Multiaddr::from_str(multiaddr.trim())
        .map_err(|e| anyhow!("{text} is not a multiaddr ({e}); e.g. /ip4/198.51.100.7/tcp/8336"))?;
    let mut parts = addr.iter();
    let host = match parts.next() {
        Some(Protocol::Ip4(ip)) => Host::Ip(ip.into()),
        Some(Protocol::Ip6(ip)) => Host::Ip(ip.into()),
        Some(Protocol::Dns(name)) => Host::Dns {
            name: name.to_string(),
            family: Family::Any,
        },
        Some(Protocol::Dns4(name)) => Host::Dns {
            name: name.to_string(),
            family: Family::V4,
        },
        Some(Protocol::Dns6(name)) => Host::Dns {
            name: name.to_string(),
            family: Family::V6,
        },
        Some(Protocol::Dnsaddr(_)) => {
            bail!("{text}: /dnsaddr lists addresses in DNS TXT records; dial one of the addresses it lists")
        }
        _ => bail!("{text}: the address must start with /ip4, /ip6, /dns, /dns4 or /dns6"),
    };
    let (carrier, port) = match parts.next() {
        Some(Protocol::Tcp(port)) => (Carrier::Tcp, port),
        Some(Protocol::Udp(port)) => match parts.next() {
            Some(Protocol::QuicV1) => (Carrier::Quic, port),
            Some(Protocol::Quic) => {
                bail!("{text}: /quic is the draft QUIC version, which the network does not use; dial /udp/{port}/quic-v1")
            }
            _ => bail!("{text}: a UDP address needs /quic-v1 after the port"),
        },
        _ => bail!("{text}: dial needs /tcp/<port> or /udp/<port>/quic-v1 after the host"),
    };
    if port == 0 {
        bail!("{text}: port 0 cannot be dialed");
    }
    let embedded = match parts.next() {
        None => None,
        Some(Protocol::P2p(id)) => Some(id),
        Some(other) => bail!("{text}: dial supports plain TCP and QUIC v1 addresses, not {other}"),
    };
    if let Some(extra) = parts.next() {
        bail!("{text}: nothing may follow /p2p/<peer-id>, found {extra}");
    }
    let flag = peer
        .map(|p| {
            PeerId::from_str(p.trim())
                .map_err(|e| anyhow!("--peer {}: not a peer ID: {e}", printable(p)))
        })
        .transpose()?;
    let expected = match (flag, embedded) {
        (Some(flag), Some(embedded)) if flag != embedded => {
            bail!("--peer {flag} and the address's /p2p/{embedded} name different peers")
        }
        (Some(peer), _) => Some(Expected {
            peer,
            source: "--peer",
        }),
        (None, Some(peer)) => Some(Expected {
            peer,
            source: "/p2p",
        }),
        (None, None) => None,
    };
    Ok(Target {
        host,
        port,
        carrier,
        expected,
    })
}

/// The socket address to dial. DNS names resolve through the system
/// resolver, which torsocks routes through Tor.
async fn resolve(target: &Target) -> anyhow::Result<SocketAddr> {
    match &target.host {
        Host::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
        Host::Dns { name, family } => {
            let name = printable(name);
            let mut addrs = tokio::net::lookup_host((name.as_str(), target.port))
                .await
                .map_err(|e| anyhow!("cannot resolve {name}: {e}"))?;
            addrs
                .find(|addr| match family {
                    Family::Any => true,
                    Family::V4 => addr.is_ipv4(),
                    Family::V6 => addr.is_ipv6(),
                })
                .ok_or_else(|| anyhow!("{name} has no address of the family its multiaddr names"))
        }
    }
}

fn dial_multiaddr(addr: SocketAddr, carrier: Carrier) -> Multiaddr {
    let mut multiaddr = Multiaddr::empty();
    multiaddr.push(match addr.ip() {
        IpAddr::V4(ip) => Protocol::Ip4(ip),
        IpAddr::V6(ip) => Protocol::Ip6(ip),
    });
    match carrier {
        Carrier::Tcp => multiaddr.push(Protocol::Tcp(addr.port())),
        Carrier::Quic => {
            multiaddr.push(Protocol::Udp(addr.port()));
            multiaddr.push(Protocol::QuicV1);
        }
    }
    multiaddr
}

/// How far the transport got, recorded by the transport itself so that a
/// failure can be told apart from the transport's layered error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Stage {
    /// No transport result yet.
    Dialing,
    /// The TCP connection is up since then; the libp2p handshake runs on it.
    TcpConnected(Instant),
    /// The socket failed before any libp2p handshake.
    Io(ErrorKind, String),
    /// QUIC: the peer never completed the handshake.
    QuicTimedOut,
    /// QUIC: the peer answered, but the handshake failed.
    QuicRejected(String),
}

fn set_stage(stage: &Mutex<Stage>, value: Stage) {
    *stage
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = value;
}

fn stage_of(stage: &Mutex<Stage>) -> Stage {
    stage
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn quic_stage(error: &libp2p::quic::Error) -> Stage {
    match error {
        libp2p::quic::Error::Io(io) => Stage::Io(io.kind(), io.to_string()),
        libp2p::quic::Error::HandshakeTimedOut => Stage::QuicTimedOut,
        libp2p::quic::Error::Connection(connection) => match connection.to_string() {
            text if text.contains("timed out") => Stage::QuicTimedOut,
            text => Stage::QuicRejected(text),
        },
        other => Stage::Io(ErrorKind::Other, other.to_string()),
    }
}

/// Why a dial failed, in terms an operator can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DialFailure {
    Refused {
        carrier: Carrier,
        endpoint: String,
    },
    NoAnswer {
        carrier: Carrier,
        endpoint: String,
        secs: u64,
    },
    HandshakeStalled {
        endpoint: String,
        secs: u64,
    },
    Handshake {
        carrier: Carrier,
        endpoint: String,
        detail: String,
    },
    PeerMismatch {
        endpoint: String,
        expected: Expected,
        actual: PeerId,
    },
    Unreachable {
        endpoint: String,
        detail: String,
    },
    Other {
        endpoint: String,
        detail: String,
    },
}

impl std::fmt::Display for DialFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialFailure::Refused { carrier: Carrier::Tcp, endpoint } => write!(
                f,
                "nothing accepts connections on {endpoint}: check port forwarding / Docker port publishing / firewall, and that the node listens on this port"
            ),
            DialFailure::Refused { carrier: Carrier::Quic, endpoint } => write!(
                f,
                "nothing accepts QUIC on {endpoint}, the host reports the port closed: check UDP port forwarding / Docker port publishing (/udp) / firewall, and that the node listens on this port"
            ),
            DialFailure::NoAnswer { carrier: Carrier::Tcp, endpoint, secs } => {
                write!(f, "no answer from {endpoint} within {secs}s: filtered by a firewall, or the host is down")
            }
            DialFailure::NoAnswer { carrier: Carrier::Quic, endpoint, secs } => write!(
                f,
                "no QUIC answer from {endpoint} within {secs}s: UDP filtered by a firewall or not forwarded, or the host is down"
            ),
            DialFailure::HandshakeStalled { endpoint, secs } => write!(
                f,
                "{endpoint} accepted the TCP connection, but the libp2p handshake did not finish within {secs}s: another service may own the port, or the node is overloaded"
            ),
            DialFailure::Handshake { carrier, endpoint, detail } => write!(
                f,
                "{endpoint} answered, but the libp2p handshake failed ({detail}): it is not a Quilibrium libp2p listener, or its release speaks another protocol than this qclient's {}",
                carrier.stack()
            ),
            DialFailure::PeerMismatch { endpoint, expected, actual } => write!(
                f,
                "{endpoint} answers as peer {actual}, not {} ({}): the address belongs to another node now, or the peer ID is wrong",
                expected.peer, expected.source
            ),
            DialFailure::Unreachable { endpoint, detail } => write!(
                f,
                "no route to {endpoint} ({detail}): check the address, and this machine's network or Tor connection"
            ),
            DialFailure::Other { endpoint, detail } => write!(f, "dialing {endpoint} failed: {detail}"),
        }
    }
}

/// The failure a transport error amounts to, given how far the transport
/// got.
pub(crate) fn classify(
    carrier: Carrier,
    stage: &Stage,
    addr: SocketAddr,
    secs: u64,
    detail: &str,
) -> DialFailure {
    let endpoint = carrier.endpoint(addr);
    let detail = printable(detail);
    match stage {
        Stage::Io(ErrorKind::ConnectionRefused, _) => DialFailure::Refused { carrier, endpoint },
        Stage::Io(ErrorKind::TimedOut, _) | Stage::QuicTimedOut => DialFailure::NoAnswer {
            carrier,
            endpoint,
            secs,
        },
        Stage::Io(ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable, io) => {
            DialFailure::Unreachable {
                endpoint,
                detail: printable(io),
            }
        }
        Stage::Io(_, io) => DialFailure::Other {
            endpoint,
            detail: printable(io),
        },
        Stage::TcpConnected(_) => DialFailure::Handshake {
            carrier,
            endpoint,
            detail,
        },
        Stage::QuicRejected(quic) => DialFailure::Handshake {
            carrier,
            endpoint,
            detail: printable(quic),
        },
        Stage::Dialing => DialFailure::Other { endpoint, detail },
    }
}

/// The failure of a dial that saw no connection within `secs`.
pub(crate) fn on_timeout(
    carrier: Carrier,
    stage: &Stage,
    addr: SocketAddr,
    secs: u64,
) -> DialFailure {
    let endpoint = carrier.endpoint(addr);
    match stage {
        Stage::TcpConnected(_) => DialFailure::HandshakeStalled { endpoint, secs },
        Stage::Dialing | Stage::QuicTimedOut => DialFailure::NoAnswer {
            carrier,
            endpoint,
            secs,
        },
        stage => classify(carrier, stage, addr, secs, "no connection"),
    }
}

/// Refuses a handshake that proved another peer ID than the one named.
pub(crate) fn verify_peer(
    expected: Option<Expected>,
    actual: PeerId,
    endpoint: String,
) -> Result<(), DialFailure> {
    match expected {
        Some(expected) if expected.peer != actual => Err(DialFailure::PeerMismatch {
            endpoint,
            expected,
            actual,
        }),
        _ => Ok(()),
    }
}

/// Every message of an error's chain, outermost first, without repeats.
/// `io::Error::source` skips the error it wraps, so it descends through
/// `get_ref` instead.
fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut next = Some(error);
    while let Some(error) = next {
        let text = error.to_string();
        if !text.is_empty() && !parts.last().is_some_and(|last| last.contains(&text)) {
            parts.push(text);
        }
        next = match error.downcast_ref::<std::io::Error>() {
            Some(io) => io
                .get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static)),
            None => error.source(),
        };
    }
    parts.join(": ")
}

fn dial_error_detail(error: &DialError) -> String {
    match error {
        DialError::Transport(errors) => match errors.first() {
            Some((_, error)) => error_chain(error),
            None => error.to_string(),
        },
        error => error.to_string(),
    }
}

fn tcp_transport(
    keypair: &Keypair,
    stage: Arc<Mutex<Stage>>,
) -> anyhow::Result<Boxed<(PeerId, StreamMuxerBox)>> {
    let security = PqNoiseConfig::new(keypair)?;
    let connected = stage.clone();
    Ok(
        libp2p::tcp::tokio::Transport::new(libp2p::tcp::Config::default())
            .map(move |stream, _| {
                set_stage(&connected, Stage::TcpConnected(Instant::now()));
                stream
            })
            .map_err(move |error: std::io::Error| {
                set_stage(&stage, Stage::Io(error.kind(), error.to_string()));
                error
            })
            .upgrade(Version::V1Lazy)
            .authenticate(security)
            .multiplex(libp2p::yamux::Config::default())
            .boxed(),
    )
}

fn quic_transport(
    keypair: &Keypair,
    timeout: Duration,
    stage: Arc<Mutex<Stage>>,
) -> Boxed<(PeerId, StreamMuxerBox)> {
    // The caller's deadline ends a silent handshake; quinn's own timers stay
    // longer so that they do not cut it short.
    let patience = timeout + Duration::from_secs(5);
    let mut config = libp2p::quic::Config::new(keypair);
    config.handshake_timeout = patience;
    config.max_idle_timeout = u32::try_from(patience.as_millis()).unwrap_or(u32::MAX);
    libp2p::quic::tokio::Transport::new(config)
        .map_err(move |error: libp2p::quic::Error| {
            set_stage(&stage, quic_stage(&error));
            error
        })
        .map(|(peer, connection), _| (peer, StreamMuxerBox::new(connection)))
        .boxed()
}

#[derive(NetworkBehaviour)]
struct DialBehaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

/// What a peer reported over identify, its text made printable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identity {
    agent_version: String,
    protocol_version: String,
    protocols: Vec<String>,
    listen_addrs: Vec<String>,
    observed_addr: String,
}

impl From<identify::Info> for Identity {
    fn from(info: identify::Info) -> Self {
        let mut protocols: Vec<String> = info
            .protocols
            .iter()
            .map(|p| printable(p.as_ref()))
            .collect();
        protocols.sort();
        protocols.dedup();
        Identity {
            agent_version: printable(&info.agent_version),
            protocol_version: printable(&info.protocol_version),
            protocols,
            listen_addrs: info
                .listen_addrs
                .iter()
                .map(|addr| addr.to_string())
                .collect(),
            observed_addr: info.observed_addr.to_string(),
        }
    }
}

/// The outcome of a dial that reached the peer.
#[derive(Debug)]
pub(crate) struct Report {
    dialed: Multiaddr,
    carrier: Carrier,
    local: PeerId,
    peer: PeerId,
    verified: Option<&'static str>,
    tcp_connect: Option<Duration>,
    established: Duration,
    identify: Result<Identity, String>,
    ping: Result<Duration, String>,
    closed: Option<String>,
}

/// Dials `addr` once as a fresh Ed25519 identity and collects what the
/// peer reports.
pub(crate) async fn dial(
    target: &Target,
    addr: SocketAddr,
    timeout: Duration,
) -> Result<Report, DialFailure> {
    let carrier = target.carrier;
    let secs = timeout.as_secs();
    let endpoint = carrier.endpoint(addr);
    let keypair = Keypair::generate_ed25519();
    let local = keypair.public().to_peer_id();
    let stage = Arc::new(Mutex::new(Stage::Dialing));
    let transport = match carrier {
        Carrier::Tcp => tcp_transport(&keypair, stage.clone()).map_err(|e| DialFailure::Other {
            endpoint: endpoint.clone(),
            detail: e.to_string(),
        })?,
        Carrier::Quic => quic_transport(&keypair, timeout, stage.clone()),
    };
    let behaviour = DialBehaviour {
        identify: identify::Behaviour::new(
            identify::Config::new(PROTOCOL_VERSION.to_string(), keypair.public())
                .with_agent_version(format!(
                    "qclient/{} diagnostics dial",
                    env!("CARGO_PKG_VERSION")
                ))
                .with_push_listen_addr_updates(false)
                .with_cache_size(0),
        ),
        ping: ping::Behaviour::new(ping::Config::new().with_timeout(timeout)),
    };
    let config =
        libp2p::swarm::Config::with_tokio_executor().with_idle_connection_timeout(timeout * 2);
    let mut swarm = Swarm::new(transport, behaviour, local, config);

    let dialed = dial_multiaddr(addr, carrier);
    let started = Instant::now();
    if let Err(error) = swarm.dial(dialed.clone()) {
        return Err(classify(
            carrier,
            &stage_of(&stage),
            addr,
            secs,
            &dial_error_detail(&error),
        ));
    }
    let mut deadline = started + timeout;
    let mut connection: Option<(PeerId, Duration)> = None;
    let mut identity: Option<Result<Identity, String>> = None;
    let mut rtt: Option<Result<Duration, String>> = None;
    let mut closed = None;
    while connection.is_none() || identity.is_none() || rtt.is_none() {
        let Ok(event) = tokio::time::timeout_at(deadline.into(), swarm.select_next_some()).await
        else {
            break;
        };
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                verify_peer(target.expected, peer_id, endpoint.clone())?;
                connection = Some((peer_id, started.elapsed()));
                deadline = Instant::now() + timeout;
            }
            SwarmEvent::OutgoingConnectionError { error, .. } => {
                return Err(classify(
                    carrier,
                    &stage_of(&stage),
                    addr,
                    secs,
                    &dial_error_detail(&error),
                ));
            }
            SwarmEvent::Behaviour(DialBehaviourEvent::Identify(identify::Event::Received {
                info,
                ..
            })) => {
                identity = Some(Ok(info.into()));
            }
            SwarmEvent::Behaviour(DialBehaviourEvent::Identify(identify::Event::Error {
                error,
                ..
            })) => {
                identity.get_or_insert_with(|| {
                    Err(format!("failed: {}", printable(&error_chain(&error))))
                });
            }
            SwarmEvent::Behaviour(DialBehaviourEvent::Ping(ping::Event { result, .. })) => {
                rtt.get_or_insert_with(|| {
                    result.map_err(|failure| match failure {
                        ping::Failure::Unsupported => "not supported by the peer".to_string(),
                        ping::Failure::Timeout => format!("no answer within {secs}s"),
                        failure => format!("failed: {}", printable(&error_chain(&failure))),
                    })
                });
            }
            SwarmEvent::ConnectionClosed { cause, .. } => {
                closed = Some(match cause {
                    Some(cause) => printable(&error_chain(&cause)),
                    None => "closed without an error".to_string(),
                });
                break;
            }
            _ => {}
        }
    }
    let Some((peer, established)) = connection else {
        return Err(on_timeout(carrier, &stage_of(&stage), addr, secs));
    };
    let tcp_connect = match stage_of(&stage) {
        Stage::TcpConnected(at) => Some(at.saturating_duration_since(started)),
        _ => None,
    };
    let unanswered = || format!("no answer within {secs}s");
    Ok(Report {
        dialed,
        carrier,
        local,
        peer,
        verified: target.expected.map(|expected| expected.source),
        tcp_connect,
        established,
        identify: identity.unwrap_or_else(|| Err(unanswered())),
        ping: rtt.unwrap_or_else(|| Err(unanswered())),
        closed,
    })
}

fn duration(d: Duration) -> String {
    if d < Duration::from_secs(10) {
        format!("{} ms", d.as_millis())
    } else {
        format!("{:.1} s", d.as_secs_f64())
    }
}

fn row(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "{label:<LABEL_WIDTH$}{value}");
}

pub(crate) fn render(report: &Report) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Dialed {} over {} as throwaway identity {}.",
        report.dialed,
        report.carrier.stack(),
        report.local
    );
    let check = match report.verified {
        Some(source) => format!("matches {source}"),
        None => "not checked: name the expected one with --peer or /p2p/<peer-id>".to_string(),
    };
    row(&mut out, "peer", &format!("{}  {check}", report.peer));
    let connected = match report.tcp_connect {
        Some(tcp) => format!(
            "{} (TCP {}, then the libp2p handshake)",
            duration(report.established),
            duration(tcp)
        ),
        None => format!("{} (QUIC handshake)", duration(report.established)),
    };
    row(&mut out, "connected", &connected);
    match &report.ping {
        Ok(rtt) => row(&mut out, "ping", &duration(*rtt)),
        Err(why) => row(&mut out, "ping", why),
    }
    match &report.identify {
        Err(why) => row(&mut out, "identify", why),
        Ok(id) => {
            let or_dash = |text: &str| {
                if text.is_empty() {
                    "-".to_string()
                } else {
                    text.to_string()
                }
            };
            row(&mut out, "agent", &or_dash(&id.agent_version));
            row(&mut out, "protocol", &or_dash(&id.protocol_version));
            row(&mut out, "observed", &or_dash(&id.observed_addr));
            let private = id
                .listen_addrs
                .iter()
                .filter(|addr| address_reach(addr) == Reach::Private)
                .count();
            row(
                &mut out,
                "listen",
                &format!("{} addresses, {private} private", id.listen_addrs.len()),
            );
            for addr in &id.listen_addrs {
                row(
                    &mut out,
                    "",
                    &format!("{:<9}{addr}", address_reach(addr).label()),
                );
            }
            row(&mut out, "protocols", &id.protocols.len().to_string());
            for protocol in &id.protocols {
                row(&mut out, "", protocol);
            }
        }
    }
    if let Some(cause) = &report.closed {
        row(
            &mut out,
            "closed",
            &format!("the connection closed early: {cause}"),
        );
    }
    out
}

/// Whether an address a peer reports can be dialed from outside its
/// network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// A globally routable IP address (documentation ranges included).
    Public,
    /// A private, loopback, link-local, shared (CGNAT) or unspecified IP
    /// address.
    Private,
    /// A DNS name, or no IP address at all: it may be either.
    Unknown,
}

impl Reach {
    fn label(self) -> &'static str {
        match self {
            Reach::Public => "public",
            Reach::Private => "private",
            Reach::Unknown => "-",
        }
    }
}

/// The [`Reach`] of a multiaddr, from its first host component.
fn address_reach(multiaddr: &str) -> Reach {
    let parts: Vec<&str> = multiaddr.trim_matches('/').split('/').collect();
    for pair in parts.chunks(2) {
        match pair {
            ["ip4", host] => return host.parse().map_or(Reach::Unknown, ipv4_reach),
            ["ip6", host] => return host.parse().map_or(Reach::Unknown, ipv6_reach),
            ["dns" | "dns4" | "dns6" | "dnsaddr", _] => return Reach::Unknown,
            _ => {}
        }
    }
    Reach::Unknown
}

fn ipv4_reach(ip: Ipv4Addr) -> Reach {
    // 100.64.0.0/10 is shared address space for carrier-grade NAT (RFC
    // 6598); `Ipv4Addr::is_shared` is not stable.
    let shared = ip.octets()[0] == 100 && (ip.octets()[1] & 0xc0) == 0x40;
    if ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_unspecified() || shared {
        Reach::Private
    } else {
        Reach::Public
    }
}

fn ipv6_reach(ip: Ipv6Addr) -> Reach {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return ipv4_reach(v4);
    }
    if ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local() || ip.is_unicast_link_local()
    {
        Reach::Private
    } else {
        Reach::Public
    }
}

/// `text` without control characters, cut to [`MAX_TEXT_CHARS`].
fn printable(text: &str) -> String {
    let mut out: String = text
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_TEXT_CHARS + 1)
        .collect();
    if out.chars().count() > MAX_TEXT_CHARS {
        out = out.chars().take(MAX_TEXT_CHARS).collect::<String>() + "…";
    }
    out
}

#[cfg(test)]
#[path = "diagnostics_dial_tests.rs"]
mod tests;
