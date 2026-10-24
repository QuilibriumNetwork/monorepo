//! `qclient node diagnostics …` — opt-in diagnostics from other nodes.
//!
//! `health` fetches a node's health report: one line per data worker with
//! its phase, frames, committee session and archive recovery counts. A node
//! serves it to itself and to the peers its operator lists in
//! `diagnostics.healthReport`; the report holds no logs, addresses or keys.
//!
//! `resolve` prints the stream address a peer publishes, from this node's
//! peer info alone, for `--addr`.
//!
//! The log request commands (`request`, `status`, `fetch`, `pending`,
//! `approve`, `deny`) are in [`super::diagnostics_logs`].

use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use clap::{Args, Subcommand};

use quil_p2p::PeerId;
use quil_rpc::diagnostics_service as diag;
use quil_types::proto::diagnostics::{
    Blocker, GetHealthReportRequest, HealthReport, Phase, RecoveryFailure, RecoveryPhase, WorkerHealth,
};
use quil_types::proto::node::PeerInfo;

use crate::commands::node::prover::local_execution::execution_label;
use crate::context::GlobalArgs;
use crate::rpc;

#[derive(Debug, Subcommand)]
pub enum DiagnosticsCommand {
    /// Fetch a node's health report: one line per data worker.
    ///
    /// Dials the target's peer listener, at the stream address it publishes
    /// (from this node's peer info) or `--addr`, with this node's network
    /// key, and refuses an endpoint that answers with another identity. The
    /// target serves the report only when its operator set
    /// `diagnostics.healthReport.enabled: true` and listed this node's peer
    /// ID in `diagnostics.healthReport.allowedPeers`, at most once per
    /// `minIntervalSecs` (60 by default) for each peer. `--self` asks this
    /// node, which always serves itself.
    ///
    /// The target sees the IP address you connect from; use a network you
    /// are willing to reveal. With --identity <file> (from `qclient
    /// diagnostics keygen`) qclient asks as that identity instead of this
    /// node and contacts no local node; then pass --addr, which `resolve`
    /// prints.
    ///
    /// Columns: PHASE is the worker's lifecycle phase (stale when its last
    /// observation is over 30s old; joining while its allocation awaits its
    /// join confirmation or activation), REASON why that phase holds (with
    /// the frame by which committed GLOBAL state ends a wait), LOCAL the
    /// worker's materialized app frame, COMMITTEE and GEN the head frame and
    /// generation of the shard's session in committed GLOBAL state as the
    /// target sees it, ADVANCE the age of LOCAL's last advance (unobserved:
    /// none since the engine started), SEAL the session's finalized seal and
    /// whether GLOBAL recorded it, RECOVERY the archive recovery phase and
    /// its attempts since the engine started, with failed attempts by class
    /// and the longest wait for a recovery turn. Ages are <60s or >60s
    /// before the report, on the target's clock.
    Health(HealthArgs),
    /// Print the stream address (host:port) a peer publishes, for --addr.
    ///
    /// Asks only this node, over its local RPC, for its peer info, and
    /// contacts no other node: the peer learns nothing of the query. It
    /// prints the master stream address the peer last announced to this
    /// node, the one `health` and the log commands dial. Those commands
    /// with --identity ask no local node, so resolve the address first and
    /// pass it on, e.g. `qclient node diagnostics health <peer> --identity
    /// <file> --addr "$(qclient node diagnostics resolve <peer>)"`. A peer
    /// this node has not heard from has no peer info here. A private,
    /// loopback, link-local or shared (CGNAT) address is unreachable from
    /// outside the peer's network: resolve skips it, and says so when the
    /// peer publishes nothing else.
    ///
    /// With --all it lists every address the peer publishes instead:
    /// KIND stream or pubsub, ADDRESS its host:port, REACH public, private
    /// (unreachable from outside the peer's network) or - (a DNS name or no
    /// IP address), MULTIADDR as published, FILTER master or the worker's
    /// shard filter.
    Resolve(ResolveArgs),
    /// Ask a peer for its redacted logs of a window of at most 24 h.
    ///
    /// Signs the request with this node's network key and adds a fresh
    /// encryption key of this request alone, whose secret stays in
    /// .diagnostics/requests until the fetch. The target queues the request
    /// only when its operator set `diagnostics.logRequests.enabled: true` and
    /// listed this node's peer ID in `diagnostics.logRequests.allowedPeers`.
    /// That listing is consent: the target's node then exports the window
    /// with the redaction of `node log export` and seals it to this request
    /// on its own, usually within minutes, or denies it when the export
    /// exceeds its maxBundleBytes. A target that writes no log files, or
    /// runs an older release, leaves it to its operator, who reviews a
    /// redacted preview first. With --filter only lines mentioning those
    /// shard filters are exported, plus every warn and error line.
    ///
    /// The target sees the IP address you connect from; use a network you
    /// are willing to reveal. With --identity <file> (from `qclient
    /// diagnostics keygen`) the request is signed by and sent as that
    /// identity instead of this node, and qclient contacts no local node;
    /// then pass --addr (`resolve` prints it), and keep the identity file
    /// for `status` and `fetch`, which need --identity too.
    Request(super::diagnostics_logs::RequestArgs),
    /// Show the state of a log request at the peer it was made to: pending,
    /// approved (fetch it), denied and by whom, or expired.
    Status(super::diagnostics_logs::PeerRequestArgs),
    /// Download an approved log request and decrypt it into a
    /// node-log-export folder (node.log.gz, manifest.json, SHA256SUMS).
    Fetch(super::diagnostics_logs::FetchArgs),
    /// List peers' log requests to this node (its operator only).
    ///
    /// A node that writes log files approves its allowlisted peers' requests
    /// itself, writing each token map to .diagnostics/token-maps; this lists
    /// them with their state until they expire. Like approve and deny, it
    /// dials this node's peer listener with this node's network key, the
    /// only key these operator commands admit: whoever holds it acts as this
    /// node's operator.
    Pending,
    /// Approve a peer's log request by hand.
    ///
    /// A node that writes log files approves its allowlisted peers'
    /// requests itself; approve is for a node that logs to the journal only,
    /// or a release that predates automatic approval. It exports the
    /// request's window and filters from this node's logs with the
    /// redaction of `node log export` and shows its preview; after you type
    /// yes (or with the global --yes) it seals the bundle to the requester's
    /// key and hands it to this node, which serves it to that peer alone
    /// until the request expires. The token map goes to
    /// .diagnostics/token-maps, owner-readable only: keep it private;
    /// approve deletes maps older than 7 days there.
    Approve(super::diagnostics_logs::DecideArgs),
    /// Deny a peer's pending log request, or withdraw an approved bundle,
    /// fetched or not, whoever approved it: this node deletes it and the
    /// peer sees it denied.
    Deny(super::diagnostics_logs::DecideArgs),
    /// Dial a node's libp2p address and print what the node reports.
    ///
    /// Tests whether a node's libp2p listener can be reached from where
    /// qclient runs, e.g. to check port forwarding. It contacts only the
    /// given address, as a throwaway Ed25519 identity made for this dial
    /// alone: it reads no key and asks no local node. It completes the
    /// handshake the network uses (PQNoise sntrup761 and yamux over TCP, or
    /// QUIC v1 with sntrup761 TLS), checks the peer ID when --peer or a
    /// trailing /p2p/<peer-id> names one, asks the peer to identify itself
    /// and pings it once.
    ///
    /// Output: peer is the peer ID the handshake proved, and whether it
    /// matches the one named; connected the time to the finished handshake
    /// (and to the TCP connection); ping one round trip; agent and protocol
    /// the software and network version the peer announces; observed the
    /// address the peer sees this dial come from; listen the addresses the
    /// peer says it listens on, each public, private (unreachable from
    /// outside the peer's network) or - (a DNS name); protocols the
    /// protocols the peer supports, sorted.
    ///
    /// Failures name their cause: a refused connection (nothing listens on
    /// the port, or it is not forwarded), no answer (filtered by a
    /// firewall, or the host is down), a failed or stalled handshake (not a
    /// Quilibrium libp2p listener) and a peer ID mismatch.
    ///
    /// The peer sees the IP address you connect from. Run under torsocks
    /// (`torsocks qclient node diagnostics dial ...`) to dial through Tor:
    /// the peer then sees a Tor exit, which observed shows. Tor carries TCP
    /// only; a QUIC dial under torsocks fails.
    Dial(super::diagnostics_dial::DialArgs),
}

#[derive(Debug, Args)]
pub struct ResolveArgs {
    /// The peer's peer ID (base58).
    pub peer: String,
    /// List every address the peer publishes, with its kind, reach and filter.
    #[arg(long)]
    pub all: bool,
}

#[derive(Debug, Args)]
pub struct HealthArgs {
    /// The target node's peer ID (base58).
    #[arg(required_unless_present = "own", conflicts_with = "own")]
    pub peer: Option<String>,
    /// Ask this node itself.
    #[arg(long = "self")]
    pub own: bool,
    /// Dial this host:port instead of the stream address the target
    /// publishes (or, with --self, this node's stream listener).
    #[arg(long)]
    pub addr: Option<String>,
    /// Ask as the diagnostics identity in this file (`qclient diagnostics
    /// keygen`) instead of this node, contacting no local node; needs --addr.
    #[arg(long, value_name = "FILE", conflicts_with = "own")]
    pub identity: Option<std::path::PathBuf>,
}

pub async fn run(global: GlobalArgs, cmd: &DiagnosticsCommand) -> anyhow::Result<()> {
    match cmd {
        DiagnosticsCommand::Dial(args) => super::diagnostics_dial::run(args).await,
        DiagnosticsCommand::Health(args) => health(global, args).await,
        DiagnosticsCommand::Request(args) => super::diagnostics_logs::request(global, args).await,
        DiagnosticsCommand::Status(args) => super::diagnostics_logs::status(global, args).await,
        DiagnosticsCommand::Fetch(args) => super::diagnostics_logs::fetch(global, args).await,
        DiagnosticsCommand::Pending => super::diagnostics_logs::pending(global).await,
        DiagnosticsCommand::Approve(args) => super::diagnostics_logs::approve(global, args).await,
        DiagnosticsCommand::Deny(args) => super::diagnostics_logs::deny(global, args).await,
        DiagnosticsCommand::Resolve(args) => resolve(global, args).await,
    }
}

async fn health(global: GlobalArgs, args: &HealthArgs) -> anyhow::Result<()> {
    let (requester, node) = super::diagnostics_logs::requester(global, args.identity.as_deref())?;
    let own = requester.peer;
    let (target, label) = match &args.peer {
        Some(peer) => {
            let target = parse_peer(peer)?;
            (target, diag::peer_tail(&target))
        }
        None => (own, "this node".to_string()),
    };
    let addr = super::diagnostics_logs::target_addr(node.as_ref(), &target, &own, args.addr.as_deref()).await?;
    let mut client = diag::connect_peer(&addr, &requester.key, target)
        .await
        .map_err(|e| anyhow::anyhow!("connect to {label} at {addr}: {}", error_chain(&*e)))?;
    match client.get_health_report(GetHealthReportRequest {}).await {
        Ok(report) => {
            print!("{}", render_report(&label, &report.into_inner()));
            Ok(())
        }
        Err(status) => {
            eprint!("{}", render_refusal(&label, &status, &own.to_base58(), requester.whose));
            anyhow::bail!("no health report from {label}")
        }
    }
}

async fn resolve(global: GlobalArgs, args: &ResolveArgs) -> anyhow::Result<()> {
    let target = parse_peer(&args.peer)?;
    let node = super::diagnostics_logs::NodeSide::load(global)
        .map_err(|e| e.context("resolve reads this node's peer info: run qclient where it finds this node's config"))?;
    let label = diag::peer_tail(&target);
    let peers = super::diagnostics_logs::local_peer_info(&node, &label).await?;
    if args.all {
        print!("{}", render_addresses(&peers, &target, &label)?);
    } else {
        println!("{}", printable(&resolve_stream_addr(&peers, &target)?));
    }
    Ok(())
}

fn parse_peer(peer: &str) -> anyhow::Result<PeerId> {
    PeerId::from_str(peer.trim()).map_err(|e| anyhow::anyhow!("{peer} is not a peer ID: {e}"))
}

pub(crate) fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text += &format!(" -> {cause}");
        source = cause.source();
    }
    text
}

/// The filter of a node's master reachability; a worker's is its shard's.
const MASTER_FILTER: [u8; 32] = [0xff; 32];

/// `target`'s entry in this node's peer info.
fn known_peer<'a>(peers: &'a [PeerInfo], target: &PeerId) -> anyhow::Result<&'a PeerInfo> {
    let id = target.to_bytes();
    peers.iter().find(|info| info.peer_id == id).ok_or_else(|| {
        anyhow::anyhow!("this node has no peer info for {target} (it learns peers from their announcements)")
    })
}

/// The `host:port` of the first stream address `target` publishes for its
/// master (the [`MASTER_FILTER`] reachability) in this node's peer info
/// that is not [`Reach::Private`]: a private one cannot be dialed from
/// outside the peer's network.
pub(crate) fn resolve_stream_addr(peers: &[PeerInfo], target: &PeerId) -> anyhow::Result<String> {
    let addrs: Vec<&String> = known_peer(peers, target)?
        .reachability
        .iter()
        .filter(|reachability| reachability.filter == MASTER_FILTER)
        .flat_map(|reachability| reachability.stream_multiaddrs.iter())
        .filter(|addr| !addr.is_empty())
        .collect();
    let Some(first) = addrs.first() else {
        anyhow::bail!("{target} publishes no stream address");
    };
    match addrs.iter().find(|addr| address_reach(addr) != Reach::Private) {
        Some(addr) => rpc::grpc_multiaddr_to_host_port(addr),
        None => {
            let shown = rpc::grpc_multiaddr_to_host_port(first).map_or_else(|_| printable(first), |a| printable(&a));
            anyhow::bail!(
                "{target} publishes only a private stream address ({shown}), unreachable from outside its \
                 network; ask its operator for a reachable host:port"
            )
        }
    }
}

/// Whether an address a peer publishes can be dialed from outside its
/// network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reach {
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
pub(crate) fn address_reach(multiaddr: &str) -> Reach {
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
    if ip.is_loopback() || ip.is_unspecified() || ip.is_unique_local() || ip.is_unicast_link_local() {
        Reach::Private
    } else {
        Reach::Public
    }
}

/// [`resolve_stream_addr`] for a command that also takes `--addr`.
pub(crate) fn published_stream_addr(peers: &[PeerInfo], target: &PeerId) -> anyhow::Result<String> {
    resolve_stream_addr(peers, target).map_err(|e| anyhow::anyhow!("{e}; pass --addr host:port"))
}

/// Every address `target` publishes in this node's peer info, in its
/// announced order: a summary line with the count of private ones, then one
/// line per address with its kind, `host:port` (`-` when it has none),
/// [`Reach`], multiaddr and filter. The addresses are the peer's text,
/// printed without control characters.
pub(crate) fn render_addresses(peers: &[PeerInfo], target: &PeerId, label: &str) -> anyhow::Result<String> {
    let mut rows = Vec::new();
    for reachability in &known_peer(peers, target)?.reachability {
        let filter = match reachability.filter.as_slice() {
            filter if filter == MASTER_FILTER => "master".to_string(),
            [] => "-".to_string(),
            filter => hex::encode(filter),
        };
        for (kind, addrs) in [("stream", &reachability.stream_multiaddrs), ("pubsub", &reachability.pubsub_multiaddrs)] {
            for addr in addrs.iter().filter(|addr| !addr.is_empty()) {
                let host_port = rpc::grpc_multiaddr_to_host_port(addr).map_or_else(|_| "-".to_string(), |a| printable(&a));
                let reach = address_reach(addr).label().to_string();
                rows.push([kind.to_string(), host_port, reach, printable(addr), filter.clone()]);
            }
        }
    }
    anyhow::ensure!(!rows.is_empty(), "{target} publishes no addresses");
    let private = rows.iter().filter(|row| row[2] == Reach::Private.label()).count();
    let header = ["KIND", "ADDRESS", "REACH", "MULTIADDR", "FILTER"].map(String::from);
    let mut widths = header.clone().map(|title| title.len());
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let mut out = format!("Addresses {label} publishes in this node's peer info: {} ({private} private).\n", rows.len());
    for cells in std::iter::once(&header).chain(&rows) {
        let [kind, host_port, reach, multiaddr, filter] = cells;
        let [kind_width, host_port_width, reach_width, multiaddr_width, _] = widths;
        let _ = writeln!(
            out,
            "{kind:<kind_width$}  {host_port:<host_port_width$}  {reach:<reach_width$}  {multiaddr:<multiaddr_width$}  {filter}"
        );
    }
    Ok(out)
}

fn release(report: &HealthReport) -> String {
    if report.version.len() != 3 {
        return "unknown".into();
    }
    let mut release = format!("{}.{}", quil_config::format_version(&report.version), report.patch);
    if report.subpatch > 0 {
        release += &format!(".{}", report.subpatch);
    }
    release
}

/// The age of `at` at the time of the report.
fn age(at: u64, now: u64) -> &'static str {
    match at {
        0 => "unobserved",
        at if now.saturating_sub(at) >= 60_000 => ">60s",
        _ => "<60s",
    }
}

fn optional(value: Option<u64>) -> String {
    value.map_or_else(|| "-".into(), |value| value.to_string())
}

fn phase(worker: &WorkerHealth, now: u64) -> String {
    let Ok(phase) = Phase::try_from(worker.phase) else { return "unrecognized".into() };
    if phase == Phase::Unspecified {
        return "unobserved".into();
    }
    // The registry's view: a joining worker may run no engine to observe.
    if phase == Phase::Joining {
        return "joining".into();
    }
    if now.saturating_sub(worker.observed_unix_ms) > diag::STALE_AFTER_MS {
        return "stale".into();
    }
    execution_label(diag::phase_name(phase)).into()
}

fn recovery(worker: &WorkerHealth, now: u64) -> String {
    let phase = RecoveryPhase::try_from(worker.recovery_phase).map_or("unrecognized", diag::recovery_phase_name);
    if worker.recovery_phase == RecoveryPhase::None as i32 && worker.recovery_attempts == 0 {
        return "-".into();
    }
    let mut text = format!(
        "{phase} {}, attempts {} ({} failing in a row)",
        age(worker.recovery_phase_since_unix_ms, now),
        worker.recovery_attempts,
        worker.recovery_consecutive_failures
    );
    let name = |class: i32| RecoveryFailure::try_from(class).map_or("unrecognized", diag::recovery_failure_name);
    if !worker.recovery_failures.is_empty() {
        let failures: Vec<String> =
            worker.recovery_failures.iter().map(|f| format!("{}:{}", name(f.class), f.count)).collect();
        text += &format!(", failed {}", failures.join(" "));
    }
    if worker.last_failure != RecoveryFailure::None as i32 {
        text += &format!(", last failure {} {}", name(worker.last_failure), age(worker.last_failure_unix_ms, now));
    }
    if worker.longest_permit_wait_ms > 0 {
        text += &format!(", longest turn wait {}s", worker.longest_permit_wait_ms / 1000);
    }
    text
}

const COLUMNS: [(&str, bool); 11] = [
    ("CORE", true),
    ("ALLOC", false),
    ("PHASE", false),
    ("REASON", false),
    ("LOCAL", true),
    ("COMMITTEE", true),
    ("GEN", false),
    ("ADVANCE", false),
    ("SEAL", false),
    ("FILTER", false),
    ("RECOVERY", false),
];

/// What a joining worker awaits: its confirm epoch, or once confirmed the
/// frame it activates at.
fn join_reason(worker: &WorkerHealth) -> Option<String> {
    match (worker.join_confirm_epoch, worker.activation_frame) {
        (Some(epoch), _) => Some(format!("awaiting join confirmation (epoch {epoch})")),
        (None, Some(frame)) => Some(format!("awaiting activation at frame {frame}")),
        (None, None) => None,
    }
}

fn row(worker: &WorkerHealth, now: u64) -> [String; 11] {
    let blocker = Blocker::try_from(worker.blocker).map_or("unrecognized", diag::blocker_text);
    let waiting = worker.phase == Phase::Waiting as i32;
    let reason = match (join_reason(worker), worker.awaited_frame) {
        (Some(join), _) if worker.phase == Phase::Joining as i32 => join,
        _ if blocker.is_empty() => "-".into(),
        // Refused only its committee seat, which committed GLOBAL state grants.
        (_, Some(frame)) if waiting && worker.blocker == Blocker::CommitteeAdmissionUnavailable as i32 =>
            format!("awaiting a committee seat (by frame {frame})"),
        (_, Some(frame)) if waiting => format!("{blocker} (by frame {frame})"),
        _ => blocker.into(),
    };
    let seal = worker.seal_generation.map_or_else(
        || "-".into(),
        |generation| {
            if worker.seal_recorded_unix_ms > 0 {
                format!("g{generation} recorded")
            } else {
                format!("g{generation} awaiting GLOBAL")
            }
        },
    );
    [
        worker.core_id.to_string(),
        if worker.allocated { "yes" } else { "no" }.into(),
        phase(worker, now),
        reason,
        optional(worker.materialized_frame),
        optional(worker.committee_head_frame),
        worker.committed_generation.map_or_else(|| "-".into(), |generation| format!("g{generation}")),
        age(worker.last_advance_unix_ms, now).into(),
        seal,
        if worker.filter.is_empty() { "-".into() } else { hex::encode(&worker.filter) },
        recovery(worker, now),
    ]
}

/// The report's line for a master store that refuses writes.
const MASTER_STORE_WRITE_FAILED: &str = "Master store stopped writing (a failed write, or free space below the \
    floor): this node cannot follow GLOBAL until the store is reopened.";

/// The report of `target` as plain text: a summary line, then one line per
/// worker.
pub(crate) fn render_report(target: &str, report: &HealthReport) -> String {
    let mut out = String::new();
    let build = report.build_fingerprint.get(..4).map_or_else(|| "unknown".into(), hex::encode);
    let omitted = match report.omitted_workers {
        0 => String::new(),
        n => format!(", {n} more not sent (report size bound)"),
    };
    let _ = writeln!(
        out,
        "Health report of {target}: release {}, build {build}, GLOBAL head frame {}; {} workers{omitted}.",
        release(report),
        report.global_head_frame,
        report.workers.len()
    );
    if report.master_store_write_failed {
        let _ = writeln!(out, "{MASTER_STORE_WRITE_FAILED}");
    }
    if report.workers.is_empty() {
        let _ = writeln!(out, "No data workers reported.");
        return out;
    }
    let rows: Vec<[String; 11]> = report.workers.iter().map(|w| row(w, report.generated_unix_ms)).collect();
    let mut widths = COLUMNS.map(|(title, _)| title.len());
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.len());
        }
    }
    let header = COLUMNS.map(|(title, _)| title.to_string());
    for cells in std::iter::once(&header).chain(&rows) {
        let mut line = String::new();
        for (index, cell) in cells.iter().enumerate() {
            let (width, right) = (widths[index], COLUMNS[index].1);
            match (index + 1 == COLUMNS.len(), right) {
                (true, _) => line += cell,
                (false, true) => line += &format!("{cell:>width$}  "),
                (false, false) => line += &format!("{cell:<width$}  "),
            }
        }
        let _ = writeln!(out, "{}", line.trim_end());
    }
    out
}

/// Longest status message shown from a target.
const MAX_MESSAGE_CHARS: usize = 200;

/// A target's status message without control characters (it is remote
/// text printed to a terminal), at most [`MAX_MESSAGE_CHARS`] long.
pub(crate) fn printable(message: &str) -> String {
    let mut text: String = message.chars().filter(|c| !c.is_control()).take(MAX_MESSAGE_CHARS + 1).collect();
    if text.chars().count() > MAX_MESSAGE_CHARS {
        text = text.chars().take(MAX_MESSAGE_CHARS).collect::<String>() + "…";
    }
    text
}

/// Why `target` did not send a report, and what would change that.
pub(crate) fn render_refusal(target: &str, status: &tonic::Status, own: &str, whose: &str) -> String {
    let message = printable(status.message());
    match status.code() {
        tonic::Code::PermissionDenied => format!(
            "{target} refused the health report ({message}).\n\
             Its operator serves it only to peers listed in that node's config:\n  \
             diagnostics:\n    healthReport:\n      enabled: true\n      allowedPeers:\n        - {own}\n\
             and a restart of that node. {own} is {whose} peer ID.\n"
        ),
        tonic::Code::ResourceExhausted => format!(
            "{target} refused the health report: {message}.\n\
             It serves each peer once per diagnostics.healthReport.minIntervalSecs (60 by default); retry after that.\n"
        ),
        tonic::Code::Unimplemented => format!("{target} does not serve health reports: its release predates them.\n"),
        code => format!("{target} did not answer the health report request: {code:?}: {message}\n"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::diagnostics::FailureCount;
    use quil_types::proto::node::Reachability;

    const NOW: u64 = 1_000_000_000;

    fn report(workers: Vec<WorkerHealth>, omitted_workers: u32) -> HealthReport {
        HealthReport {
            schema: 1,
            version: vec![2, 1, 0],
            patch: 25,
            subpatch: 88,
            build_fingerprint: vec![0xab; 32],
            global_head_frame: 90_001,
            generated_unix_ms: NOW,
            workers,
            omitted_workers,
            master_store_write_failed: false,
        }
    }

    fn two_workers() -> Vec<WorkerHealth> {
        let mut serving = WorkerHealth {
            core_id: 1,
            filter: vec![0xa1; 32],
            allocated: true,
            observed_unix_ms: NOW - 1_000,
            materialized_frame: Some(1_204),
            last_advance_unix_ms: NOW - 5_000,
            committee_head_frame: Some(1_204),
            committed_generation: Some(7),
            recovery_phase_since_unix_ms: NOW - 600_000,
            recovery_attempts: 1,
            last_success_unix_ms: NOW - 600_000,
            ..Default::default()
        };
        serving.set_phase(Phase::Serving);
        serving.set_recovery_phase(RecoveryPhase::Idle);
        let mut blocked = WorkerHealth {
            core_id: 12,
            filter: vec![0xb2; 32],
            allocated: true,
            observed_unix_ms: NOW - 2_000,
            materialized_frame: Some(1_180),
            last_advance_unix_ms: NOW - 900_000,
            committee_head_frame: Some(1_204),
            committed_generation: Some(7),
            recovery_phase_since_unix_ms: NOW - 120_000,
            recovery_attempts: 5,
            recovery_consecutive_failures: 2,
            recovery_failures: vec![
                FailureCount { class: RecoveryFailure::Connect as i32, count: 2 },
                FailureCount { class: RecoveryFailure::ArchiveState as i32, count: 1 },
            ],
            last_failure_unix_ms: NOW - 30_000,
            longest_permit_wait_ms: 95_000,
            seal_generation: Some(6),
            ..Default::default()
        };
        blocked.set_phase(Phase::Blocked);
        blocked.set_blocker(Blocker::StateUnavailable);
        blocked.set_recovery_phase(RecoveryPhase::InstallingLeaves);
        blocked.set_last_failure(RecoveryFailure::Connect);
        vec![serving, blocked]
    }

    #[test]
    fn a_report_renders_one_line_per_worker() {
        let text = render_report("…Ab12cd", &report(two_workers(), 0));
        let a1 = "a1".repeat(32);
        let b2 = "b2".repeat(32);
        assert_eq!(text, format!("\
Health report of …Ab12cd: release 2.1.0.25.88, build abababab, GLOBAL head frame 90001; 2 workers.
CORE  ALLOC  PHASE    REASON             LOCAL  COMMITTEE  GEN  ADVANCE  SEAL                FILTER                                                            RECOVERY
   1  yes    serve    -                   1204       1204  g7   <60s     -                   {a1}  idle >60s, attempts 1 (0 failing in a row)
  12  yes    blocked  state unavailable   1180       1204  g7   >60s     g6 awaiting GLOBAL  {b2}  installing_leaves >60s, attempts 5 (2 failing in a row), failed connect:2 archive_state:1, last failure connect <60s, longest turn wait 95s
"));
    }

    #[test]
    fn stale_unobserved_and_unallocated_workers_say_so() {
        let mut stale = two_workers().remove(0);
        stale.observed_unix_ms = NOW - 31_000;
        let unallocated = WorkerHealth { core_id: 3, ..Default::default() };
        let text = render_report("this node", &report(vec![stale, unallocated], 4));
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[0].ends_with("; 2 workers, 4 more not sent (report size bound)."), "{}", lines[0]);
        assert!(lines[2].contains(" stale "), "{}", lines[2]);
        assert_eq!(lines[3], "   3  no     unobserved  -           -          -  -    unobserved  -     -                                                                 -");
    }

    /// A joining worker says what it awaits instead of reading as
    /// unobserved or blocked; its recovery stays in its column.
    #[test]
    fn a_joining_worker_names_its_confirm_epoch_or_activation_frame() {
        let mut unconfirmed = WorkerHealth {
            core_id: 4,
            filter: vec![0xc3; 32],
            allocated: true,
            join_confirm_epoch: Some(1_276),
            activation_frame: Some(919_440),
            ..Default::default()
        };
        unconfirmed.set_phase(Phase::Joining);
        let mut activating = two_workers().remove(1);
        activating.set_phase(Phase::Joining);
        activating.set_blocker(Blocker::ConsensusStartupUnavailable);
        activating.activation_frame = Some(918_720);
        let text = render_report("this node", &report(vec![unconfirmed, activating], 0));
        let lines: Vec<&str> = text.lines().collect();
        assert!(lines[2].starts_with("   4  yes    joining  awaiting join confirmation (epoch 1276)  "), "{}", lines[2]);
        assert!(lines[3].starts_with("  12  yes    joining  awaiting activation at frame 918720      "), "{}", lines[3]);
        assert!(lines[3].ends_with("installing_leaves >60s, attempts 5 (2 failing in a row), failed connect:2 \
            archive_state:1, last failure connect <60s, longest turn wait 95s"), "{}", lines[3]);

        let mut seat = two_workers().remove(1);
        seat.set_phase(Phase::Waiting);
        seat.set_blocker(Blocker::CommitteeAdmissionUnavailable);
        seat.awaited_frame = Some(919_440);
        let text = render_report("this node", &report(vec![seat], 0));
        assert!(text.lines().nth(2).unwrap().starts_with("  12  yes    wait   awaiting a committee seat (by frame 919440)  "),
            "{text}");
    }

    #[test]
    fn a_master_store_refusing_writes_is_named() {
        let mut latched = report(Vec::new(), 0);
        latched.master_store_write_failed = true;
        let text = render_report("this node", &latched);
        assert_eq!(text.lines().nth(1), Some(MASTER_STORE_WRITE_FAILED), "{text}");
        assert!(MASTER_STORE_WRITE_FAILED.contains("free space below the floor"), "{MASTER_STORE_WRITE_FAILED}");
        assert!(!render_report("this node", &report(Vec::new(), 0)).contains("Master store"));
    }

    #[test]
    fn an_empty_report_says_no_workers() {
        assert_eq!(render_report("…Ab12cd", &report(Vec::new(), 0)),
            "Health report of …Ab12cd: release 2.1.0.25.88, build abababab, GLOBAL head frame 90001; 0 workers.\n\
             No data workers reported.\n");
    }

    #[test]
    fn a_refusal_names_what_the_target_operator_must_configure() {
        let denied = tonic::Status::permission_denied(diag::DENIED);
        assert_eq!(render_refusal("…Ab12cd", &denied, "QmOwnPeerId", "this node's"), "\
…Ab12cd refused the health report (diagnostics unavailable).
Its operator serves it only to peers listed in that node's config:
  diagnostics:
    healthReport:
      enabled: true
      allowedPeers:
        - QmOwnPeerId
and a restart of that node. QmOwnPeerId is this node's peer ID.
");
        let limited = tonic::Status::resource_exhausted("a health report was served to this peer less than 60s ago");
        assert!(render_refusal("…Ab12cd", &limited, "QmOwnPeerId", "this node's").contains("minIntervalSecs"));
        let old = tonic::Status::unimplemented("");
        assert!(render_refusal("…Ab12cd", &old, "QmOwnPeerId", "this node's").contains("predates"));
    }

    /// A target's message reaches the terminal without escape sequences
    /// and within a bounded length.
    #[test]
    fn a_refusal_message_is_printable_and_bounded() {
        let hostile = tonic::Status::unavailable(format!("\x1b]0;owned\x07\x1b[2Jbusy\r\nretry{}", "x".repeat(500)));
        let text = render_refusal("…Ab12cd", &hostile, "QmOwnPeerId", "this node's");
        assert!(text.starts_with("…Ab12cd did not answer the health report request: Unavailable: ]0;owned[2Jbusyretryxxx"), "{text}");
        assert!(!text.trim_end_matches('\n').chars().any(char::is_control), "{text:?}");
        assert_eq!(printable(hostile.message()).chars().count(), MAX_MESSAGE_CHARS + 1);
        assert_eq!(printable("short"), "short");
    }

    #[test]
    fn the_published_master_stream_address_is_dialed() {
        let key = |n: u8| quil_p2p::Keypair::falcon_from_bytes(&quil_p2p::generate_falcon_signing_key())
            .map(|k| (k.public().to_peer_id(), n)).unwrap();
        let ((target, _), (other, _), (silent, _)) = (key(1), key(2), key(3));
        let reach = |filter: Vec<u8>, stream: &str| Reachability {
            filter,
            pubsub_multiaddrs: vec!["/ip4/192.0.2.1/udp/8336/quic-v1".into()],
            stream_multiaddrs: vec![stream.into()],
        };
        let peers = vec![
            PeerInfo { peer_id: other.to_bytes(), reachability: vec![reach(vec![0xff; 32], "/ip4/192.0.2.9/tcp/8340")], ..Default::default() },
            PeerInfo {
                peer_id: target.to_bytes(),
                reachability: vec![reach(vec![0x01; 32], "/ip4/192.0.2.5/tcp/50001"), reach(vec![0xff; 32], "/ip4/192.0.2.4/tcp/8340")],
                ..Default::default()
            },
            PeerInfo { peer_id: silent.to_bytes(), reachability: vec![reach(vec![0xff; 32], "")], ..Default::default() },
        ];
        assert_eq!(published_stream_addr(&peers, &target).unwrap(), "192.0.2.4:8340");
        assert!(published_stream_addr(&peers, &silent).unwrap_err().to_string().contains("publishes no stream address"));
        let unknown = key(4).0;
        assert!(published_stream_addr(&peers, &unknown).unwrap_err().to_string().contains("no peer info"));
    }

    fn peer() -> PeerId {
        quil_p2p::Keypair::falcon_from_bytes(&quil_p2p::generate_falcon_signing_key()).unwrap().public().to_peer_id()
    }

    fn reach(filter: Vec<u8>, stream: &[&str], pubsub: &[&str]) -> Reachability {
        Reachability {
            filter,
            pubsub_multiaddrs: pubsub.iter().map(|addr| addr.to_string()).collect(),
            stream_multiaddrs: stream.iter().map(|addr| addr.to_string()).collect(),
        }
    }

    fn info(peer: &PeerId, reachability: Vec<Reachability>) -> PeerInfo {
        PeerInfo { peer_id: peer.to_bytes(), reachability, ..Default::default() }
    }

    #[test]
    fn resolve_prints_the_master_stream_address_or_says_what_is_missing() {
        let (target, workers_only, silent, unknown) = (peer(), peer(), peer(), peer());
        let peers = vec![
            info(&workers_only, vec![reach(vec![0x01; 32], &["/ip4/192.0.2.5/tcp/50001"], &[])]),
            info(
                &target,
                vec![
                    reach(vec![0x01; 32], &["/ip4/192.0.2.5/tcp/50001"], &["/ip4/192.0.2.4/udp/8336/quic-v1"]),
                    reach(vec![0xff; 32], &["", "/ip4/192.0.2.4/tcp/8340", "/ip4/192.0.2.6/tcp/8340"], &[]),
                ],
            ),
            info(&silent, Vec::new()),
        ];
        assert_eq!(resolve_stream_addr(&peers, &target).unwrap(), "192.0.2.4:8340");
        for (who, why) in [(&workers_only, "publishes no stream address"), (&silent, "publishes no stream address"), (&unknown, "no peer info")] {
            let error = resolve_stream_addr(&peers, who).unwrap_err().to_string();
            assert!(error.contains(why) && error.contains(&who.to_base58()) && !error.contains("--addr"), "{error}");
            let error = published_stream_addr(&peers, who).unwrap_err().to_string();
            assert!(error.contains(why) && error.ends_with("; pass --addr host:port"), "{error}");
        }
    }

    #[test]
    fn all_lists_every_published_address_with_its_kind_and_filter() {
        let (target, other) = (peer(), peer());
        let peers = vec![
            info(&other, vec![reach(vec![0xff; 32], &["/ip4/192.0.2.9/tcp/8340"], &[])]),
            info(
                &target,
                vec![
                    reach(vec![0xff; 32], &["/ip4/192.0.2.4/tcp/8340"], &["/ip4/192.0.2.4/udp/8336/quic-v1"]),
                    reach(vec![0x01; 32], &["/ip4/192.0.2.5/tcp/50001", ""], &[]),
                    reach(Vec::new(), &[], &["/ip6/2001:db8::1/udp/8336/quic-v1", "/p2p-circuit"]),
                ],
            ),
        ];
        let w = "01".repeat(32);
        assert_eq!(render_addresses(&peers, &target, "…Ab12cd").unwrap(), format!("\
Addresses …Ab12cd publishes in this node's peer info: 5 (0 private).
KIND    ADDRESS             REACH   MULTIADDR                          FILTER
stream  192.0.2.4:8340      public  /ip4/192.0.2.4/tcp/8340            master
pubsub  192.0.2.4:8336      public  /ip4/192.0.2.4/udp/8336/quic-v1    master
stream  192.0.2.5:50001     public  /ip4/192.0.2.5/tcp/50001           {w}
pubsub  [2001:db8::1]:8336  public  /ip6/2001:db8::1/udp/8336/quic-v1  -
pubsub  -                   -       /p2p-circuit                       -
"));
    }

    #[test]
    fn all_says_when_a_peer_is_unknown_or_publishes_nothing() {
        let (target, silent, unknown) = (peer(), peer(), peer());
        let hostile = "/ip4/192.0.2.7/tcp/8340\u{1b}[2J\r";
        let peers = vec![
            info(&target, vec![reach(vec![0xff; 32], &[hostile], &[])]),
            info(&silent, vec![reach(vec![0xff; 32], &[""], &[""])]),
        ];
        let text = render_addresses(&peers, &target, "…Ab12cd").unwrap();
        assert!(text.contains("/ip4/192.0.2.7/tcp/8340[2J") && !text.chars().any(|c| c.is_control() && c != '\n'), "{text:?}");
        let error = render_addresses(&peers, &silent, "…Ab12cd").unwrap_err().to_string();
        assert!(error.contains("publishes no addresses"), "{error}");
        let error = render_addresses(&peers, &unknown, "…Ab12cd").unwrap_err().to_string();
        assert!(error.contains("no peer info"), "{error}");
    }

    #[test]
    fn addresses_are_classified_by_whether_they_reach_outside_their_network() {
        let cases = [
            ("/ip4/192.0.2.4/tcp/8340", Reach::Public),
            ("/ip4/198.51.100.7/tcp/8340", Reach::Public),
            ("/ip4/8.8.8.8/tcp/8340", Reach::Public),
            ("/ip4/9.255.255.255/tcp/8340", Reach::Public),
            ("/ip4/10.0.0.1/tcp/8340", Reach::Private),
            ("/ip4/10.255.255.255/tcp/8340", Reach::Private),
            ("/ip4/11.0.0.0/tcp/8340", Reach::Public),
            ("/ip4/172.15.255.255/tcp/8340", Reach::Public),
            ("/ip4/172.16.0.1/tcp/8340", Reach::Private),
            ("/ip4/172.31.255.255/tcp/8340", Reach::Private),
            ("/ip4/172.32.0.0/tcp/8340", Reach::Public),
            ("/ip4/192.167.255.255/tcp/8340", Reach::Public),
            ("/ip4/192.168.1.5/tcp/8336", Reach::Private),
            ("/ip4/192.169.0.0/tcp/8340", Reach::Public),
            ("/ip4/100.63.255.255/tcp/8340", Reach::Public),
            ("/ip4/100.64.0.1/tcp/8340", Reach::Private),
            ("/ip4/100.127.255.255/tcp/8340", Reach::Private),
            ("/ip4/100.128.0.0/tcp/8340", Reach::Public),
            ("/ip4/127.0.0.1/tcp/8340", Reach::Private),
            ("/ip4/169.254.1.1/tcp/8340", Reach::Private),
            ("/ip4/0.0.0.0/tcp/8340", Reach::Private),
            ("/ip6/2001:db8::1/udp/8336/quic-v1", Reach::Public),
            ("/ip6/2606:4700::1/tcp/8340", Reach::Public),
            ("/ip6/::1/tcp/8340", Reach::Private),
            ("/ip6/::/tcp/8340", Reach::Private),
            ("/ip6/fc00::1/tcp/8340", Reach::Private),
            ("/ip6/fd00::1/tcp/8340", Reach::Private),
            ("/ip6/fbff:ffff::1/tcp/8340", Reach::Public),
            ("/ip6/fe80::1/tcp/8340", Reach::Private),
            ("/ip6/febf::1/tcp/8340", Reach::Private),
            ("/ip6/fec0::1/tcp/8340", Reach::Public),
            ("/ip6/::ffff:192.168.1.5/tcp/8340", Reach::Private),
            ("/ip6/::ffff:192.0.2.4/tcp/8340", Reach::Public),
            ("/dns4/node.example.invalid/tcp/8340", Reach::Unknown),
            ("/dns/localhost/tcp/8340", Reach::Unknown),
            ("/p2p-circuit", Reach::Unknown),
            ("/ip4/not-an-ip/tcp/8340", Reach::Unknown),
            ("", Reach::Unknown),
        ];
        for (addr, reach) in cases {
            assert_eq!(address_reach(addr), reach, "{addr}");
        }
    }

    #[test]
    fn resolve_skips_a_private_stream_address_and_says_when_only_private_ones_remain() {
        let (mixed, private_only, named) = (peer(), peer(), peer());
        let peers = vec![
            info(
                &mixed,
                vec![
                    reach(vec![0xff; 32], &["/ip4/192.168.1.5/tcp/8340", "/ip6/fd00::5/tcp/8340"], &["/ip4/192.168.1.5/tcp/8336"]),
                    reach(vec![0xff; 32], &["/ip4/192.0.2.4/tcp/8340"], &[]),
                ],
            ),
            info(
                &private_only,
                vec![reach(vec![0xff; 32], &["", "/ip4/10.1.2.3/tcp/8340", "/ip4/100.64.0.1/tcp/8340"], &["/ip4/192.0.2.8/tcp/8336"])],
            ),
            info(&named, vec![reach(vec![0xff; 32], &["/ip4/127.0.0.1/tcp/8340", "/dns4/node.example.invalid/tcp/8340"], &[])]),
        ];
        assert_eq!(resolve_stream_addr(&peers, &mixed).unwrap(), "192.0.2.4:8340");
        assert_eq!(published_stream_addr(&peers, &mixed).unwrap(), "192.0.2.4:8340");
        assert_eq!(resolve_stream_addr(&peers, &named).unwrap(), "node.example.invalid:8340");
        let error = resolve_stream_addr(&peers, &private_only).unwrap_err().to_string();
        assert_eq!(
            error,
            format!(
                "{private_only} publishes only a private stream address (10.1.2.3:8340), unreachable from outside its \
                 network; ask its operator for a reachable host:port"
            )
        );
        let error = published_stream_addr(&peers, &private_only).unwrap_err().to_string();
        assert!(error.contains("publishes only a private stream address") && error.ends_with("; pass --addr host:port"), "{error}");
    }

    #[test]
    fn all_marks_the_private_addresses_a_peer_publishes() {
        let target = peer();
        let peers = vec![info(
            &target,
            vec![
                reach(vec![0xff; 32], &["/ip4/192.0.2.4/tcp/8340", "/ip4/192.168.1.5/tcp/8340"], &["/ip4/172.16.0.1/tcp/8336"]),
                reach(Vec::new(), &[], &["/ip6/fe80::1/udp/8336/quic-v1", "/dns4/node.example.invalid/tcp/8336"]),
            ],
        )];
        assert_eq!(render_addresses(&peers, &target, "…Ab12cd").unwrap(), "\
Addresses …Ab12cd publishes in this node's peer info: 5 (3 private).
KIND    ADDRESS                    REACH    MULTIADDR                            FILTER
stream  192.0.2.4:8340             public   /ip4/192.0.2.4/tcp/8340              master
stream  192.168.1.5:8340           private  /ip4/192.168.1.5/tcp/8340            master
pubsub  172.16.0.1:8336            private  /ip4/172.16.0.1/tcp/8336             master
pubsub  [fe80::1]:8336             private  /ip6/fe80::1/udp/8336/quic-v1        -
pubsub  node.example.invalid:8336  -        /dns4/node.example.invalid/tcp/8336  -
");
    }
}
