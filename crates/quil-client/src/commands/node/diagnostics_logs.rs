//! `qclient node diagnostics request|status|fetch|pending|approve|deny` —
//! a peer's redacted logs, sent as its operator's allowlist consents.
//!
//! The requester signs a [`LogRequest`] with its node's network key and a
//! fresh sntrup761 key of that request, whose secret stays in this node's
//! `.diagnostics/requests`. The target queues it and, when it writes log
//! files, approves it itself: listing the requester in its allowedPeers is
//! that consent. A target that writes no log files leaves it to its
//! operator, who lists it with `pending` and runs `approve`, which exports
//! the window with `node log export`'s redaction and preview, seals the
//! bundle to the request's key and hands it to the operator's own node.
//! Either way the export and seal are [`bundle`]'s. Only the requester's
//! qclient can `fetch` and open it; the token map stays with the target.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use rand::RngCore;
use sha2::{Digest, Sha256};

use quil_p2p::PeerId;
use quil_rpc::diagnostics_logs as logs;
use quil_rpc::diagnostics_logs::bundle::{self, Approval, BUNDLE_FILES};
use quil_rpc::diagnostics_service::peer_tail;
use quil_rpc::log_export::{self, redact::format_rfc3339_utc, BUNDLE_LOG};
use quil_types::proto::diagnostics::{
    DenyLogRequestRequest, FetchLogBundleRequest, GetLogRequestStatusRequest,
    ListLogRequestsRequest, ListLogRequestsResponse, LogRequest, LogRequestDenial,
    LogRequestRefusal, LogRequestStatus, LogRequestStatusResponse, PendingLogRequest,
    SubmitLogRequestResponse, UploadLogBundleChunk,
};

use super::diagnostics::{error_chain, printable};
use super::log::export::{self, LogSource};
use crate::context::{Context, GlobalArgs};
use crate::rpc;

#[derive(Debug, Args)]
pub struct RequestArgs {
    /// The target node's peer ID (base58).
    pub peer: String,
    /// Window start: UTC RFC 3339 (2026-10-17T16:00:00Z) or a time ago
    /// (6h, 90m).
    #[arg(long)]
    pub since: String,
    /// Window end: UTC RFC 3339 or a time ago (default now). The window is
    /// at most 24 h.
    #[arg(long)]
    pub until: Option<String>,
    /// Export only lines mentioning this full hex shard filter
    /// (repeatable, at most 16); warn and error lines are always kept.
    #[arg(long = "filter", value_name = "HEX")]
    pub filters: Vec<String>,
    /// Dial this host:port instead of the stream address the target
    /// publishes.
    #[arg(long)]
    pub addr: Option<String>,
    /// Ask as the diagnostics identity in this file (`qclient diagnostics
    /// keygen`) instead of this node, contacting no local node; needs --addr.
    #[arg(long, value_name = "FILE")]
    pub identity: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct PeerRequestArgs {
    /// The target node's peer ID (base58).
    pub peer: String,
    /// The request ID, or its first 8 or more hex digits.
    pub request: String,
    /// Dial this host:port instead of the stream address the target
    /// publishes.
    #[arg(long)]
    pub addr: Option<String>,
    /// Ask as the diagnostics identity in this file (`qclient diagnostics
    /// keygen`) instead of this node, contacting no local node; needs --addr.
    #[arg(long, value_name = "FILE")]
    pub identity: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct FetchArgs {
    #[command(flatten)]
    pub request: PeerRequestArgs,
    /// Bundle directory (default ./node-log-export-<UTC time>-<peer>).
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct DecideArgs {
    /// The request ID, or its first 8 or more hex digits, as `pending`
    /// lists it.
    pub request: String,
}

/// The largest sealed bundle `fetch` accepts.
const MAX_FETCH_BYTES: u64 = 256 * 1024 * 1024;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn now_secs() -> i64 {
    (now_ms() / 1000) as i64
}

/// `ms` from now as a short span: `3h 5m`, `12m`, `<1m`.
fn span(ms: u64) -> String {
    let minutes = ms / 60_000;
    match (minutes / 60, minutes % 60) {
        (0, 0) => "<1m".into(),
        (0, m) => format!("{m}m"),
        (h, 0) => format!("{h}h"),
        (h, m) => format!("{h}h {m}m"),
    }
}

fn window_text(since: u64, until: u64) -> String {
    match (i64::try_from(since), i64::try_from(until)) {
        (Ok(since), Ok(until)) => format!(
            "{} .. {} (UTC)",
            format_rfc3339_utc(since),
            format_rfc3339_utc(until)
        ),
        _ => "an invalid window".to_string(),
    }
}

/// The window of `since`/`until` at `now`, at most 24 h.
pub(crate) fn parse_window(
    since: &str,
    until: Option<&str>,
    now: i64,
) -> anyhow::Result<(u64, u64)> {
    let until = match until {
        Some(until) => log_export::parse_when(until, now)?,
        None => now,
    };
    let since = log_export::parse_when(since, now)?;
    anyhow::ensure!(since < until, "--since must be before --until");
    anyhow::ensure!(
        (until - since) as u64 <= logs::MAX_WINDOW_SECS,
        "the window is longer than 24 h; narrow --since/--until"
    );
    anyhow::ensure!(since >= 0, "--since is before 1970");
    Ok((since as u64, until as u64))
}

/// Full public shard filters from hex.
pub(crate) fn parse_filters(filters: &[String]) -> anyhow::Result<Vec<Vec<u8>>> {
    anyhow::ensure!(
        filters.len() <= logs::MAX_FILTERS,
        "at most {} --filter values",
        logs::MAX_FILTERS
    );
    filters
        .iter()
        .map(|text| {
            let hex_text = text.trim().trim_start_matches("0x");
            let filter = hex::decode(hex_text)
                .map_err(|_| anyhow::anyhow!("--filter {text}: expected a hex shard filter"))?;
            anyhow::ensure!(
                logs::SHARD_FILTER_BYTES.contains(&filter.len()),
                "--filter {text}: a full shard filter has {} to {} bytes",
                logs::SHARD_FILTER_BYTES.start(),
                logs::SHARD_FILTER_BYTES.end()
            );
            Ok(filter)
        })
        .collect()
}

/// The unique ID among `ids` that starts with the hex `prefix` (8 or more
/// digits).
pub(crate) fn resolve_id<'a>(
    ids: impl IntoIterator<Item = &'a [u8]>,
    prefix: &str,
) -> anyhow::Result<Vec<u8>> {
    let prefix = prefix.trim().to_ascii_lowercase();
    anyhow::ensure!(
        prefix.len() >= 8
            && prefix.len() <= 2 * logs::ID_LEN
            && prefix.bytes().all(|b| b.is_ascii_hexdigit()),
        "{prefix}: a request ID is 8 to 32 hex digits"
    );
    let matches: Vec<&[u8]> = ids
        .into_iter()
        .filter(|id| hex::encode(id).starts_with(&prefix))
        .collect();
    match matches.as_slice() {
        [id] => Ok(id.to_vec()),
        [] => anyhow::bail!("no log request {prefix}"),
        _ => anyhow::bail!(
            "{prefix} names {} log requests; give more digits",
            matches.len()
        ),
    }
}

/// The peer ID of the Falcon network key `key`, as the peer listener's
/// handshake proves it.
fn falcon_peer(key: &[u8]) -> anyhow::Result<PeerId> {
    Ok(quil_p2p::Keypair::falcon_from_bytes(key)
        .map_err(|e| anyhow::anyhow!("not a Falcon network key: {e}"))?
        .public()
        .to_peer_id())
}

/// The node's network key and peer ID.
fn network_key(
    ctx: &Context,
    node_config: &quil_config::Config,
    dir: &Path,
) -> anyhow::Result<(Vec<u8>, PeerId)> {
    let key = ctx
        .key_manager(node_config, dir)?
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get q-prover-key for transport auth: {e}"))?
        .private_key()
        .to_vec();
    let own = falcon_peer(&key).map_err(|e| e.context("this node's network identity"))?;
    Ok((key, own))
}

/// The local node, when a requester asks as it.
pub(crate) struct NodeSide {
    pub ctx: Context,
    pub config: quil_config::Config,
    pub dir: PathBuf,
}

impl NodeSide {
    pub(crate) fn load(global: GlobalArgs) -> anyhow::Result<Self> {
        let ctx = Context::load(global)?;
        let (config, dir) = ctx.load_node_config("default")?;
        Ok(Self { ctx, config, dir })
    }
}

/// Who asks another node: a network key, its peer ID, and where the secret
/// keys of its requests stay.
pub(crate) struct Requester {
    pub key: Vec<u8>,
    pub peer: PeerId,
    pub requests_dir: PathBuf,
    /// "this node's" or "this identity's", for messages.
    pub whose: &'static str,
}

const NO_REQUESTER: &str =
    "no network key to ask with: run qclient where it finds this node's config and keys, \
    or pass --identity <file> (create one with `qclient diagnostics keygen --out <file>`)";

/// The requester of `identity`, which reads no local node, or else this
/// node, which `node` loads; never one in place of the other.
pub(crate) fn requester_with(
    identity: Option<&Path>,
    node: impl FnOnce() -> anyhow::Result<NodeSide>,
) -> anyhow::Result<(Requester, Option<NodeSide>)> {
    if let Some(path) = identity {
        let key = load_identity(path)?;
        let peer = falcon_peer(&key)?;
        let requests_dir = export::with_suffix(path, ".requests");
        return Ok((
            Requester {
                key,
                peer,
                requests_dir,
                whose: "this identity's",
            },
            None,
        ));
    }
    let node = node().map_err(|e| e.context(NO_REQUESTER))?;
    let (key, peer) =
        network_key(&node.ctx, &node.config, &node.dir).map_err(|e| e.context(NO_REQUESTER))?;
    let requests_dir = requests_dir(&node.dir);
    Ok((
        Requester {
            key,
            peer,
            requests_dir,
            whose: "this node's",
        },
        Some(node),
    ))
}

/// The requester for a command's `--identity`.
pub(crate) fn requester(
    global: GlobalArgs,
    identity: Option<&Path>,
) -> anyhow::Result<(Requester, Option<NodeSide>)> {
    requester_with(identity, || NodeSide::load(global))
}

fn label(node: Option<&NodeSide>, requester: &Requester, target: &PeerId) -> String {
    if node.is_some() && *target == requester.peer {
        "this node".to_string()
    } else {
        peer_tail(target)
    }
}

/// Diagnostics identities.
#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    /// Generate a diagnostics identity and print its peer ID.
    ///
    /// Writes a fresh Falcon network key to --out, owner-readable only, and
    /// never over an existing file. With --identity <file>, `qclient node
    /// diagnostics health|request|status|fetch` ask other nodes as this
    /// identity instead of as your node and contact no local node; a
    /// target's operator lists its peer ID in allowedPeers. It is not a
    /// prover key: it cannot join, sign or earn as a prover. The target
    /// still sees the IP address you connect from; use a network you are
    /// willing to reveal.
    Keygen {
        /// The identity file to create.
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
}

pub fn run_identity(cmd: &IdentityCommand) -> anyhow::Result<()> {
    match cmd {
        IdentityCommand::Keygen { out } => {
            println!("{}", keygen(out)?);
            Ok(())
        }
    }
}

const IDENTITY_HEADER: &str =
    "# qclient diagnostics identity: a Falcon network key, not a prover key. PRIVATE: do not share.";

/// Write a fresh identity to `out`, never over a file; its peer ID.
pub(crate) fn keygen(out: &Path) -> anyhow::Result<PeerId> {
    anyhow::ensure!(
        !out.exists(),
        "{} exists; keygen never overwrites an identity",
        out.display()
    );
    let key = quil_p2p::generate_falcon_signing_key();
    let peer = falcon_peer(&key)?;
    write_private(
        out,
        format!("{IDENTITY_HEADER}\n{}\n", hex::encode(&key)).as_bytes(),
    )?;
    Ok(peer)
}

/// The network key of the identity file `path`.
pub(crate) fn load_identity(path: &Path) -> anyhow::Result<Vec<u8>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("read the identity {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        anyhow::ensure!(
            mode & 0o077 == 0,
            "the identity {} is readable by others; chmod 600 it",
            path.display()
        );
    }
    let hex_text: String = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let key = hex::decode(hex_text).unwrap_or_default();
    anyhow::ensure!(
        key.len() == quil_crypto::FALCON_SIGNING_KEY_LEN
            && quil_crypto::falcon_public_from_signing_key(&key).is_some(),
        "{} is not a diagnostics identity (`qclient diagnostics keygen` makes one)",
        path.display()
    );
    Ok(key)
}

fn parse_target(peer: &str) -> anyhow::Result<PeerId> {
    logs::parse_peer(peer).ok_or_else(|| anyhow::anyhow!("{peer} is not a peer ID"))
}

/// The address of `target`'s peer listener: `addr`, this node's own, or the
/// one `target` publishes in this node's peer info. Without a node (an
/// identity requester) only `addr`.
pub(crate) async fn target_addr(
    node: Option<&NodeSide>,
    target: &PeerId,
    own: &PeerId,
    addr: Option<&str>,
) -> anyhow::Result<String> {
    if let Some(addr) = addr {
        return Ok(addr.to_string());
    }
    let Some(node) = node else {
        anyhow::bail!(
            "with --identity, pass --addr host:port of the target's peer listener (the stream address it \
             publishes): qclient asks no local node for it; `qclient node diagnostics resolve {target}` \
             prints it from your node's peer info"
        );
    };
    if target == own {
        return rpc::local_stream_addr(&node.config);
    }
    let peers = local_peer_info(node, &peer_tail(target))
        .await
        .map_err(|e| anyhow::anyhow!("{e:#} Or pass --addr host:port"))?;
    super::diagnostics::published_stream_addr(&peers, target)
}

/// This node's peer info, from its local RPC. Refuses a qclient configured
/// for a public or custom RPC: that would ask another node, which learns
/// of the query and whose peer info is not this node's.
pub(crate) async fn local_peer_info(
    node: &NodeSide,
    label: &str,
) -> anyhow::Result<Vec<quil_types::proto::node::PeerInfo>> {
    let opts = node.ctx.connect_opts(&node.config, false);
    local_only(&opts, label)?;
    let mut client = rpc::connect_node_service(&opts).await.map_err(|e| {
        anyhow::anyhow!("ask this node for the address of {label}: {e}; is it running?")
    })?;
    Ok(client
        .get_peer_info(quil_types::proto::node::GetPeerInfoRequest {})
        .await
        .map_err(|e| anyhow::anyhow!("ask this node for its peer info: {}.", e.message()))?
        .into_inner()
        .peer_info)
}

/// Refuses connection options that reach a public or custom RPC instead
/// of this node.
fn local_only(opts: &rpc::ConnectOpts, label: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !opts.is_light_node(),
        "qclient's config sets publicRpc or customRpc, so it would ask that RPC rather than this node for the \
         address of {label}."
    );
    Ok(())
}

fn private_dir(dir: &Path) -> anyhow::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", dir.display()))
}

fn write_private(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", path.display()))?;
    file.write_all(data)
        .map_err(|e| anyhow::anyhow!("write {}: {e}", path.display()))
}

/// The secret key of one request this node made, kept until its fetch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct RequestKey {
    pub target: String,
    pub request_id: String,
    pub kem_secret_key: String,
    pub since_unix: u64,
    pub until_unix: u64,
}

fn requests_dir(config_dir: &Path) -> PathBuf {
    config_dir.join(".diagnostics").join("requests")
}

fn save_request_key(dir: &Path, key: &RequestKey) -> anyhow::Result<PathBuf> {
    private_dir(dir)?;
    let path = dir.join(format!("{}.json", key.request_id));
    write_private(&path, serde_json::to_string_pretty(key)?.as_bytes())?;
    Ok(path)
}

/// The keys of the requests to `target` kept in `dir`, with their files.
fn request_keys(dir: &Path, target: &PeerId) -> Vec<(PathBuf, RequestKey, Vec<u8>)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            let key: RequestKey = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
            let id = hex::decode(&key.request_id).ok()?;
            (key.target == target.to_base58()).then_some((path, key, id))
        })
        .collect()
}

/// Write fetched bundle files into a new directory `out`.
fn write_bundle(out: &Path, files: &[Vec<u8>]) -> anyhow::Result<()> {
    anyhow::ensure!(!out.exists(), "{} already exists", out.display());
    let staging = export::with_suffix(out, ".partial");
    anyhow::ensure!(!staging.exists(), "{} already exists", staging.display());
    std::fs::create_dir_all(&staging)
        .map_err(|e| anyhow::anyhow!("create {}: {e}", staging.display()))?;
    let mut guard = export::StagingGuard(Some(staging.clone()));
    for (name, data) in BUNDLE_FILES.iter().zip(files) {
        std::fs::write(staging.join(name), data)?;
    }
    std::fs::rename(&staging, out)
        .map_err(|e| anyhow::anyhow!("rename to {}: {e}", out.display()))?;
    guard.0 = None;
    Ok(())
}

/// What a peer's refusal of any log request call means.
pub(crate) fn render_call_refusal(
    target: &str,
    status: &tonic::Status,
    own: &str,
    whose: &str,
) -> String {
    let message = printable(status.message());
    match status.code() {
        tonic::Code::PermissionDenied => format!(
            "{target} refused the log request ({message}).\n\
             Its operator accepts requests only from peers listed in that node's config:\n  \
             diagnostics:\n    logRequests:\n      enabled: true\n      allowedPeers:\n        - {own}\n\
             and a restart of that node. {own} is {whose} peer ID.\n"
        ),
        tonic::Code::NotFound => format!("{target} knows no such log request from this node.\n"),
        tonic::Code::Unimplemented => format!("{target} does not take log requests: its release predates them.\n"),
        code => format!("{target} did not answer the log request call: {code:?}: {message}\n"),
    }
}

fn refusal_text(refusal: LogRequestRefusal) -> &'static str {
    match refusal {
        LogRequestRefusal::None => "no reason given",
        LogRequestRefusal::Malformed => "it could not read the request; is its release older than this one?",
        LogRequestRefusal::WrongTarget => "the request names another node",
        LogRequestRefusal::Stale => "the request's time or window end is more than 10 minutes from its clock; check both clocks",
        LogRequestRefusal::Replayed => "it saw the request's nonce before; ask again",
        LogRequestRefusal::WindowTooLong => "the window is longer than 24 h",
        LogRequestRefusal::TooManyFilters => "more than 16 filters",
        LogRequestRefusal::OverBudget => "this node used its requests for the last 24 h (diagnostics.logRequests.requestsPerDay)",
        LogRequestRefusal::QueueFull => "its queue is full (diagnostics.logRequests.maxPending); ask again later",
        LogRequestRefusal::FilterLength => "a filter is not a full shard filter of 32 to 64 bytes",
        LogRequestRefusal::TooManyPending => {
            "this requester's requests awaiting a decision or a fetch hold its share of the queue (half of \
             diagnostics.logRequests.maxPending); fetch the approved ones, or wait for the others to be decided; a node \
             of an earlier release frees a place only when its request expires"
        }
    }
}

/// The target's report of this requester's budget of requests in the last
/// 24 h and, once none are left, when the next is possible. Nothing from a
/// node of an earlier release, which reports no budget.
fn budget_lines(response: &SubmitLogRequestResponse) -> String {
    let (Some(remaining), Some(per_day)) = (response.requests_remaining, response.requests_per_day)
    else {
        return String::new();
    };
    let mut out = format!("Requests left: {remaining} of {per_day} per 24 h.\n");
    if let Some(next_ms) = response.next_request_unix_ms.filter(|_| remaining == 0) {
        let secs = i64::try_from(next_ms.saturating_add(999) / 1000).unwrap_or(i64::MAX);
        let _ = writeln!(
            out,
            "Next request possible at {} (UTC).",
            format_rfc3339_utc(secs)
        );
    }
    out
}

/// The answer to a submitted request.
pub(crate) fn render_submitted(
    target: &str,
    peer: &str,
    since: u64,
    until: u64,
    filters: usize,
    response: &SubmitLogRequestResponse,
    now_ms: u64,
) -> String {
    let id = hex::encode(&response.request_id);
    let short = logs::short_id(&response.request_id);
    let filters = match filters {
        0 => "every line".to_string(),
        1 => "lines of 1 shard filter".to_string(),
        n => format!("lines of {n} shard filters"),
    };
    let mut out = String::new();
    match response.status() {
        LogRequestStatus::Refused => {
            let _ = writeln!(
                out,
                "{target} refused log request {short}: {}.",
                refusal_text(response.refusal())
            );
            out.push_str(&budget_lines(response));
        }
        status => {
            let _ = writeln!(
                out,
                "Asked {target} for {filters} of {}: request {id}.",
                window_text(since, until)
            );
            let expires = span(response.expires_unix_ms.saturating_sub(now_ms));
            let _ = match status {
                LogRequestStatus::Pending if response.automatic => writeln!(out,
                    "{target} approves it itself, as its operator allows for this peer: it exports the window with \
                     'node log export' redaction and seals it to this request's key, usually within minutes; \
                     it expires in {expires} unless approved."),
                LogRequestStatus::Pending => writeln!(out,
                    "It waits for {target}'s operator, who sees a redacted preview before anything is sent; \
                     it expires in {expires} unless approved."),
                status => writeln!(out, "It was submitted before and is {}.", logs::status_name(status)),
            };
            out.push_str(&budget_lines(response));
            let _ = writeln!(
                out,
                "Check it with: qclient node diagnostics status {peer} {short}"
            );
            let _ = writeln!(
                out,
                "Once approved, fetch it with: qclient node diagnostics fetch {peer} {short}"
            );
        }
    }
    out
}

/// The state of a request.
pub(crate) fn render_status(
    target: &str,
    peer: &str,
    response: &LogRequestStatusResponse,
    now_ms: u64,
) -> String {
    let id = hex::encode(&response.request_id);
    let short = &id[..8.min(id.len())];
    let expires = span(response.expires_unix_ms.saturating_sub(now_ms));
    match response.status() {
        LogRequestStatus::Pending => format!(
            "Request {short} at {target}: pending: its node is exporting it, or its operator has yet to approve it; \
             expires in {expires}.\n"
        ),
        LogRequestStatus::Ready | LogRequestStatus::Served => format!(
            "Request {short} at {target}: approved, {} sealed bytes{}; fetchable for {expires}.\n\
             Fetch it with: qclient node diagnostics fetch {peer} {short}\n",
            response.bundle_bytes,
            if response.status() == LogRequestStatus::Served { ", fetched before" } else { "" }
        ),
        LogRequestStatus::Denied => match response.denial() {
            LogRequestDenial::Operator => format!("Request {short} at {target}: denied by its operator.\n"),
            LogRequestDenial::TooLarge => format!(
                "Request {short} at {target}: denied by its node: the export exceeds its \
                 diagnostics.logRequests.maxBundleBytes; ask for a shorter window or fewer shard filters.\n"
            ),
            LogRequestDenial::ExportFailed => format!(
                "Request {short} at {target}: denied by its node: its export failed, for a reason its log names; \
                 ask again later.\n"
            ),
        },
        LogRequestStatus::Expired => format!("Request {short} at {target}: expired before it was approved or fetched.\n"),
        status => format!("Request {short} at {target}: {}.\n", logs::status_name(status)),
    }
}

/// This node's queue of peers' log requests.
pub(crate) fn render_pending(list: &ListLogRequestsResponse, now_ms: u64) -> String {
    let mut out = String::new();
    if list.requests.is_empty() {
        let _ = writeln!(out, "No log requests from peers.");
        return out;
    }
    let _ = writeln!(out, "Log requests from peers: {}.", list.requests.len());
    let rows: Vec<[String; 6]> = list
        .requests
        .iter()
        .map(|request| {
            [
                logs::short_id(&request.request_id),
                logs::peer_from_bytes(&request.requester_peer_id)
                    .map_or_else(|| "unknown".into(), |peer| peer_tail(&peer)),
                logs::status_name(request.status()).to_string(),
                window_text(request.since_unix, request.until_unix),
                if request.filters.is_empty() {
                    "all".to_string()
                } else {
                    request.filters.len().to_string()
                },
                span(request.expires_unix_ms.saturating_sub(now_ms)),
            ]
        })
        .collect();
    let header = [
        "REQUEST",
        "FROM",
        "STATUS",
        "WINDOW",
        "FILTERS",
        "EXPIRES IN",
    ]
    .map(String::from);
    let mut widths = header.clone().map(|title| title.len());
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    for cells in std::iter::once(&header).chain(&rows) {
        let mut line = String::new();
        for (cell, width) in cells.iter().zip(widths) {
            let _ = write!(line, "{cell:<width$}  ");
        }
        let _ = writeln!(out, "{}", line.trim_end());
    }
    for request in list
        .requests
        .iter()
        .filter(|request| !request.filters.is_empty())
    {
        let _ = writeln!(out, "Filters of {}:", logs::short_id(&request.request_id));
        for filter in &request.filters {
            let _ = writeln!(out, "  {}", hex::encode(filter));
        }
    }
    if list.automatic {
        let _ = writeln!(out,
            "This node approves these requests itself, as its allowedPeers consent: it exports each window with \
             'node log export' redaction and seals it to the requester. Deny one with \
             'qclient node diagnostics deny <request>', which also withdraws an approved bundle, fetched or not.");
    } else if list
        .requests
        .iter()
        .any(|request| request.status() == LogRequestStatus::Pending)
    {
        let _ = writeln!(out,
            "Approve one with 'qclient node diagnostics approve <request>': it exports that window with \
             'node log export' redaction and shows a preview before sending; deny it with \
             'qclient node diagnostics deny <request>', which also withdraws an approved bundle.");
    }
    out
}

/// Refuse an answer for another request than the one sent.
pub(crate) fn check_submitted(
    id: &[u8],
    response: &SubmitLogRequestResponse,
    target: &str,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        response.request_id == id,
        "{target} answered for another request than {}; its answer is ignored",
        logs::short_id(id)
    );
    Ok(())
}

/// Delete the key of a request the target denied or let expire: it has
/// nothing left to fetch. The line to print, when it did.
pub(crate) fn settle_key(status: LogRequestStatus, key: Option<&Path>) -> Option<String> {
    let key =
        key.filter(|_| matches!(status, LogRequestStatus::Denied | LogRequestStatus::Expired))?;
    std::fs::remove_file(key).ok()?;
    Some("Its key is deleted: there is nothing left to fetch.\n".to_string())
}

/// The preview line naming where an approved bundle goes.
fn destination(request: &PendingLogRequest) -> String {
    let requester = logs::peer_from_bytes(&request.requester_peer_id)
        .map_or_else(|| "unknown".into(), |peer| peer_tail(&peer));
    format!(
        "Destination: sealed to request {} of {requester}, whose qclient alone can open it; this node keeps \
         the sealed bundle until it is fetched or expires.",
        logs::short_id(&request.request_id)
    )
}

/// The sealed upload of `sealed` for request `id`.
pub(crate) fn upload_chunks(id: &[u8], sealed: &[u8]) -> Vec<UploadLogBundleChunk> {
    let sha256 = Sha256::digest(sealed).to_vec();
    sealed
        .chunks(logs::UPLOAD_CHUNK_BYTES)
        .enumerate()
        .map(|(n, data)| UploadLogBundleChunk {
            request_id: if n == 0 { id.to_vec() } else { Vec::new() },
            total_bytes: if n == 0 { sealed.len() as u64 } else { 0 },
            sha256: if n == 0 { sha256.clone() } else { Vec::new() },
            data: data.to_vec(),
        })
        .collect()
}

/// Open a fetched bundle with the request's secret key.
pub(crate) fn open_fetched(sealed: &[u8], key: &RequestKey) -> anyhow::Result<Vec<Vec<u8>>> {
    let id = hex::decode(&key.request_id)?;
    let secret = hex::decode(&key.kem_secret_key)?;
    let plaintext = quil_crypto::seal::open(sealed, &secret, &id)
        .map_err(|_| anyhow::anyhow!("the bundle does not open with this request's key"))?;
    bundle::unpack_bundle(&plaintext)
}

pub async fn request(global: GlobalArgs, args: &RequestArgs) -> anyhow::Result<()> {
    let (who, node) = requester(global, args.identity.as_deref())?;
    let target = parse_target(&args.peer)?;
    let label = label(node.as_ref(), &who, &target);
    let now_ms = now_ms();
    let (since, until) = parse_window(&args.since, args.until.as_deref(), now_secs())?;
    let filters = parse_filters(&args.filters)?;
    let kem = quil_crypto::Sntrup761KeyPair::generate();
    let mut nonce = vec![0u8; logs::NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let public = quil_crypto::falcon_public_from_signing_key(&who.key)
        .ok_or_else(|| anyhow::anyhow!("the network key is not a Falcon key"))?;
    let request = LogRequest {
        schema: logs::REQUEST_SCHEMA,
        target_peer_id: target.to_bytes(),
        requester_public_key: public,
        issued_unix_ms: now_ms,
        nonce,
        since_unix: since,
        until_unix: until,
        filters: filters.clone(),
        recipient_kem_public_key: kem.public.clone(),
    };
    let signed = logs::sign_request(&request, &who.key)?;
    let id = logs::request_id(&signed.request);
    let addr = target_addr(node.as_ref(), &target, &who.peer, args.addr.as_deref()).await?;
    let mut client = logs::connect_log_peer(&addr, &who.key, target)
        .await
        .map_err(|e| anyhow::anyhow!("connect to {label} at {addr}: {}", error_chain(&*e)))?;
    let record = RequestKey {
        target: target.to_base58(),
        request_id: hex::encode(id),
        kem_secret_key: hex::encode(&kem.secret),
        since_unix: since,
        until_unix: until,
    };
    let key_path = save_request_key(&who.requests_dir, &record)?;
    let peer = target.to_base58();
    match client
        .submit_log_request(logs::timed(signed, logs::CALL_TIMEOUT))
        .await
    {
        Ok(response) => {
            let response = response.into_inner();
            if let Err(error) = check_submitted(&id, &response, &label) {
                let _ = std::fs::remove_file(&key_path);
                return Err(error);
            }
            print!(
                "{}",
                render_submitted(
                    &label,
                    &peer,
                    since,
                    until,
                    filters.len(),
                    &response,
                    now_ms
                )
            );
            if response.status() == LogRequestStatus::Refused {
                let _ = std::fs::remove_file(&key_path);
                anyhow::bail!("log request refused by {label}");
            }
            Ok(())
        }
        Err(status) => {
            let _ = std::fs::remove_file(&key_path);
            eprint!(
                "{}",
                render_call_refusal(&label, &status, &who.peer.to_base58(), who.whose)
            );
            anyhow::bail!("no log request queued at {label}")
        }
    }
}

/// The ID of `args.request`: a request this node holds the key of, or a
/// full ID.
fn peer_request_id(
    dir: &Path,
    target: &PeerId,
    text: &str,
) -> anyhow::Result<(Vec<u8>, Option<(PathBuf, RequestKey)>)> {
    let keys = request_keys(dir, target);
    match resolve_id(keys.iter().map(|(_, _, id)| id.as_slice()), text) {
        Ok(id) => {
            let (path, key, _) = keys
                .into_iter()
                .find(|(_, _, k)| *k == id)
                .expect("resolved from these keys");
            Ok((id, Some((path, key))))
        }
        Err(_) if text.len() == 2 * logs::ID_LEN => Ok((hex::decode(text.trim())?, None)),
        Err(error) => Err(error.context(format!(
            "this node holds no key for a request {text} to {}",
            peer_tail(target)
        ))),
    }
}

pub async fn status(global: GlobalArgs, args: &PeerRequestArgs) -> anyhow::Result<()> {
    let (who, node) = requester(global, args.identity.as_deref())?;
    let target = parse_target(&args.peer)?;
    let label = label(node.as_ref(), &who, &target);
    let (id, held) = peer_request_id(&who.requests_dir, &target, &args.request)?;
    let addr = target_addr(node.as_ref(), &target, &who.peer, args.addr.as_deref()).await?;
    let mut client = logs::connect_log_peer(&addr, &who.key, target)
        .await
        .map_err(|e| anyhow::anyhow!("connect to {label} at {addr}: {}", error_chain(&*e)))?;
    match client
        .get_log_request_status(logs::timed(
            GetLogRequestStatusRequest { request_id: id },
            logs::CALL_TIMEOUT,
        ))
        .await
    {
        Ok(response) => {
            let response = response.into_inner();
            print!(
                "{}",
                render_status(&label, &target.to_base58(), &response, now_ms())
            );
            if let Some(line) = settle_key(
                response.status(),
                held.as_ref().map(|(path, _)| path.as_path()),
            ) {
                print!("{line}");
            }
            Ok(())
        }
        Err(status) => {
            eprint!(
                "{}",
                render_call_refusal(&label, &status, &who.peer.to_base58(), who.whose)
            );
            anyhow::bail!("no status from {label}")
        }
    }
}

pub async fn fetch(global: GlobalArgs, args: &FetchArgs) -> anyhow::Result<()> {
    let (who, node) = requester(global, args.request.identity.as_deref())?;
    let target = parse_target(&args.request.peer)?;
    let label = label(node.as_ref(), &who, &target);
    let (id, Some((key_path, request_key))) =
        peer_request_id(&who.requests_dir, &target, &args.request.request)?
    else {
        anyhow::bail!("this node holds no key for that request; only the qclient that made a request can open its bundle");
    };
    let base58 = target.to_base58();
    let tail = &base58[base58.len().saturating_sub(6)..];
    let out: PathBuf = args.out.clone().unwrap_or_else(|| {
        PathBuf::from(format!(
            "node-log-export-{}-{tail}",
            log_export::compact_ts(now_secs())
        ))
    });
    anyhow::ensure!(!out.exists(), "{} already exists", out.display());
    let addr = target_addr(
        node.as_ref(),
        &target,
        &who.peer,
        args.request.addr.as_deref(),
    )
    .await?;
    let mut client = logs::connect_log_peer(&addr, &who.key, target)
        .await
        .map_err(|e| anyhow::anyhow!("connect to {label} at {addr}: {}", error_chain(&*e)))?;
    let fetch = FetchLogBundleRequest {
        request_id: id.clone(),
        offset: 0,
    };
    let mut stream = match client
        .fetch_log_bundle(logs::timed(fetch, logs::CALL_TIMEOUT))
        .await
    {
        Ok(stream) => stream.into_inner(),
        Err(status) => {
            eprint!(
                "{}",
                render_call_refusal(&label, &status, &who.peer.to_base58(), who.whose)
            );
            anyhow::bail!("no bundle from {label}")
        }
    };
    let mut sealed = Vec::new();
    let mut expected: Option<(u64, Vec<u8>)> = None;
    // A chunk is at most 256 KiB: each may take the unary timeout, never the whole bundle.
    while let Some(chunk) = tokio::time::timeout(logs::CALL_TIMEOUT, stream.message())
        .await
        .map_err(|_| anyhow::anyhow!("{label} stopped sending the bundle; fetch again"))?
        .map_err(|s| anyhow::anyhow!("fetch from {label}: {}", printable(s.message())))?
    {
        let (total, sha256) =
            expected.get_or_insert_with(|| (chunk.total_bytes, chunk.sha256.clone()));
        anyhow::ensure!(
            *total <= MAX_FETCH_BYTES,
            "{label} offers a bundle of {total} bytes, over {MAX_FETCH_BYTES}"
        );
        anyhow::ensure!(
            chunk.offset == sealed.len() as u64
                && chunk.total_bytes == *total
                && chunk.sha256 == *sha256,
            "{label} sent the bundle out of order"
        );
        anyhow::ensure!(
            sealed.len() as u64 + chunk.data.len() as u64 <= *total,
            "{label} sent more than the bundle"
        );
        sealed.extend_from_slice(&chunk.data);
    }
    let (total, sha256) = expected.ok_or_else(|| anyhow::anyhow!("{label} sent no bundle"))?;
    anyhow::ensure!(
        sealed.len() as u64 == total,
        "the transfer from {label} ended at {} of {total} bytes; fetch again",
        sealed.len()
    );
    anyhow::ensure!(
        Sha256::digest(&sealed).as_slice() == sha256.as_slice(),
        "the bundle from {label} does not match its SHA-256; fetch again"
    );
    let files = open_fetched(&sealed, &request_key)?;
    write_bundle(&out, &files)?;
    let _ = std::fs::remove_file(&key_path);
    let lines = serde_json::from_slice::<serde_json::Value>(&files[1])
        .ok()
        .and_then(|m| m["lines"]["kept"].as_u64());
    print!(
        "{}",
        render_fetched(
            &label,
            &out,
            &id,
            lines,
            request_key.since_unix,
            request_key.until_unix
        )
    );
    Ok(())
}

pub(crate) fn render_fetched(
    target: &str,
    out: &Path,
    id: &[u8],
    lines: Option<u64>,
    since: u64,
    until: u64,
) -> String {
    let lines = lines.map_or_else(|| "an unknown number of".to_string(), |n| n.to_string());
    format!(
        "Wrote {} ({BUNDLE_LOG}, manifest.json, SHA256SUMS): {lines} redacted lines of {target}, {}, request {}.\n\
         The request's key is deleted; {target}'s operator keeps the token map.\n",
        out.display(),
        window_text(since, until),
        logs::short_id(id)
    )
}

async fn operator(global: GlobalArgs) -> anyhow::Result<(Context, PathBuf, logs::OperatorClient)> {
    let ctx = Context::load(global)?;
    let (node_config, dir) = ctx.load_node_config("default")?;
    let (key, _) = network_key(&ctx, &node_config, &dir)?;
    let addr = rpc::local_stream_addr(&node_config)?;
    let client = logs::connect_operator(&addr, &key).await.map_err(|e| {
        anyhow::anyhow!(
            "connect to this node's peer listener at {addr}: {}; is it running?",
            error_chain(&*e)
        )
    })?;
    Ok((ctx, dir, client))
}

async fn list(client: &mut logs::OperatorClient) -> anyhow::Result<ListLogRequestsResponse> {
    client
        .list_log_requests(logs::timed(ListLogRequestsRequest {}, logs::CALL_TIMEOUT))
        .await
        .map(tonic::Response::into_inner)
        .map_err(|s| {
            anyhow::anyhow!(
                "this node did not list its log requests: {:?}: {}",
                s.code(),
                printable(s.message())
            )
        })
}

pub async fn pending(global: GlobalArgs) -> anyhow::Result<()> {
    let (_, _, mut client) = operator(global).await?;
    print!("{}", render_pending(&list(&mut client).await?, now_ms()));
    Ok(())
}

pub async fn deny(global: GlobalArgs, args: &DecideArgs) -> anyhow::Result<()> {
    let (_, _, mut client) = operator(global).await?;
    let requests = list(&mut client).await?.requests;
    let id = resolve_id(
        requests.iter().map(|r| r.request_id.as_slice()),
        &args.request,
    )?;
    let request = requests
        .iter()
        .find(|r| r.request_id == id)
        .expect("resolved from this list");
    client
        .deny_log_request(logs::timed(
            DenyLogRequestRequest {
                request_id: id.clone(),
            },
            logs::CALL_TIMEOUT,
        ))
        .await
        .map_err(|s| anyhow::anyhow!("deny {}: {}", logs::short_id(&id), printable(s.message())))?;
    print!("{}", render_denied(request));
    Ok(())
}

/// What deny did to `request`, as it was before.
pub(crate) fn render_denied(request: &PendingLogRequest) -> String {
    let requester = logs::peer_from_bytes(&request.requester_peer_id)
        .map_or_else(|| "unknown".into(), |peer| peer_tail(&peer));
    let id = logs::short_id(&request.request_id);
    match request.status() {
        LogRequestStatus::Pending => format!("Denied log request {id} from {requester}.\n"),
        status => format!(
            "Withdrew the approved bundle of log request {id} from {requester} ({}): this node deleted it.\n",
            if status == LogRequestStatus::Served { "fetched before" } else { "not fetched yet" }
        ),
    }
}

pub async fn approve(global: GlobalArgs, args: &DecideArgs) -> anyhow::Result<()> {
    let (ctx, dir, mut client) = operator(global).await?;
    let listed = list(&mut client).await?;
    let id = resolve_id(
        listed.requests.iter().map(|r| r.request_id.as_slice()),
        &args.request,
    )?;
    let request = listed
        .requests
        .iter()
        .find(|r| r.request_id == id)
        .expect("resolved from this list")
        .clone();
    anyhow::ensure!(
        request.status() == LogRequestStatus::Pending,
        "log request {} is {}, not pending",
        logs::short_id(&id),
        logs::status_name(request.status())
    );
    let requester = logs::peer_from_bytes(&request.requester_peer_id)
        .map_or_else(|| "unknown".into(), |peer| peer_tail(&peer));
    let selection =
        bundle::request_selection(request.since_unix, request.until_unix, &request.filters)?;
    let max = usize::try_from(listed.max_bundle_bytes).unwrap_or(usize::MAX);
    let (readers, source, child) = export::open_source(
        &ctx.global,
        LogSource::Auto,
        selection.since,
        selection.until,
    )?;
    let home_paths = [dir.clone()];
    let options = log_export::ExportOptions {
        home_paths: &home_paths,
        ..Default::default()
    };
    let produced = bundle::request_export(
        readers,
        child,
        &source,
        &selection,
        &id,
        &requester,
        Approval::Operator,
        max,
        &options,
    )
    .map_err(too_large_advice)?;
    let maps = dir.join(".diagnostics").join("token-maps");
    let pruned = bundle::prune_token_maps(
        &maps,
        std::time::SystemTime::now(),
        bundle::TOKEN_MAP_RETENTION,
    );
    if pruned > 0 {
        println!(
            "Deleted {pruned} token map(s) older than 7 days from {}.",
            maps.display()
        );
    }
    let map_path = maps.join(bundle::token_map_name(&id, now_secs()));
    println!("Log request {} from {requester}:", logs::short_id(&id));
    print!(
        "{}",
        log_export::preview(
            &produced.manifest,
            &produced.stats,
            &destination(&request),
            &map_path
        )
    );
    if !export::confirm(
        &ctx.global,
        &format!("Type yes to seal the bundle and send it to {requester}: "),
    )? {
        println!("Nothing sent. The request stays pending until it expires; deny it with 'qclient node diagnostics deny {}'.", logs::short_id(&id));
        return Ok(());
    }
    let sealed = bundle::seal_export(produced, &id, &request.recipient_kem_public_key, max)
        .map_err(too_large_advice)?;
    private_dir(&maps)?;
    log_export::write_token_map(
        &map_path,
        &format!("log request {} of {requester}", logs::short_id(&id)),
        &sealed.token_map,
    )?;
    let sealed = sealed.sealed;
    let upload = logs::timed(
        futures::stream::iter(upload_chunks(&id, &sealed)),
        logs::upload_timeout(sealed.len() as u64),
    );
    match client.upload_log_bundle(upload).await {
        Ok(response) => {
            let expires = span(
                response
                    .into_inner()
                    .expires_unix_ms
                    .saturating_sub(now_ms()),
            );
            print!(
                "{}",
                render_approved(&requester, &id, sealed.len(), &expires, &map_path)
            );
            Ok(())
        }
        Err(status) => {
            let _ = std::fs::remove_file(&map_path);
            anyhow::bail!(
                "this node did not take the bundle: {:?}: {}",
                status.code(),
                printable(status.message())
            )
        }
    }
}

/// `error`, with what the operator can do when the export is over
/// `maxBundleBytes`.
fn too_large_advice(error: anyhow::Error) -> anyhow::Error {
    if !bundle::is_too_large(&error) {
        return error;
    }
    anyhow::anyhow!("{error:#}; deny the request and ask for a narrower window or filters, or raise the limit and restart")
}

pub(crate) fn render_approved(
    requester: &str,
    id: &[u8],
    bytes: usize,
    expires: &str,
    map_path: &Path,
) -> String {
    format!(
        "Approved log request {} of {requester}: this node serves the {bytes}-byte sealed bundle to that peer alone, \
         for {expires}.\nThe token map {} holds the original values: keep it private and never share it.\n",
        logs::short_id(id),
        map_path.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message as _;
    use quil_rpc::diagnostics_logs::bundle::{pack_bundle, unpack_bundle, Capped};

    const NOW: u64 = 1_792_000_000_000;

    #[test]
    fn peer_info_is_asked_only_of_this_node() {
        let local = rpc::ConnectOpts {
            listen_grpc_multiaddr: "/ip4/127.0.0.1/tcp/8337".into(),
            ..Default::default()
        };
        assert!(local_only(&local, "…Ab12cd").is_ok());
        assert!(local_only(&rpc::ConnectOpts::default(), "…Ab12cd").is_ok());
        let public = rpc::ConnectOpts {
            public_rpc: true,
            ..local.clone()
        };
        let custom = rpc::ConnectOpts {
            custom_rpc: "rpc.example.invalid:8337".into(),
            ..Default::default()
        };
        for opts in [public, custom] {
            let error = local_only(&opts, "…Ab12cd").unwrap_err().to_string();
            assert!(
                error.contains("publicRpc or customRpc") && error.contains("…Ab12cd"),
                "{error}"
            );
        }
    }

    fn pending_request(
        id: u8,
        status: LogRequestStatus,
        filters: Vec<Vec<u8>>,
    ) -> PendingLogRequest {
        let mut request = PendingLogRequest {
            request_id: vec![id; 16],
            requester_peer_id: Vec::new(),
            received_unix_ms: NOW - 600_000,
            expires_unix_ms: NOW + 23 * 3_600_000 + 50 * 60_000,
            since_unix: 1_791_978_400,
            until_unix: 1_792_000_000,
            filters,
            ..Default::default()
        };
        request.set_status(status);
        request
    }

    #[test]
    fn the_pending_list_shows_each_request_and_what_to_do() {
        let list = ListLogRequestsResponse {
            requests: vec![
                pending_request(
                    0x3f,
                    LogRequestStatus::Pending,
                    vec![vec![0xa1; 32], vec![0xb2; 32]],
                ),
                pending_request(0x5e, LogRequestStatus::Ready, Vec::new()),
            ],
            max_bundle_bytes: 1 << 25,
            automatic: false,
        };
        let a1 = "a1".repeat(32);
        let b2 = "b2".repeat(32);
        assert_eq!(render_pending(&list, NOW), format!("\
Log requests from peers: 2.
REQUEST   FROM     STATUS   WINDOW                                              FILTERS  EXPIRES IN
3f3f3f3f  unknown  pending  2026-10-14T11:46:40Z .. 2026-10-14T17:46:40Z (UTC)  2        23h 50m
5e5e5e5e  unknown  ready    2026-10-14T11:46:40Z .. 2026-10-14T17:46:40Z (UTC)  all      23h 50m
Filters of 3f3f3f3f:
  {a1}
  {b2}
Approve one with 'qclient node diagnostics approve <request>': it exports that window with 'node log export' redaction and shows a preview before sending; deny it with 'qclient node diagnostics deny <request>', which also withdraws an approved bundle.
"));
        let automatic = render_pending(
            &ListLogRequestsResponse {
                automatic: true,
                ..list.clone()
            },
            NOW,
        );
        assert!(automatic.ends_with("\
This node approves these requests itself, as its allowedPeers consent: it exports each window with 'node log export' redaction and seals it to the requester. Deny one with 'qclient node diagnostics deny <request>', which also withdraws an approved bundle, fetched or not.
"), "{automatic}");
        assert!(!automatic.contains("Approve one"), "{automatic}");
        assert_eq!(
            render_pending(&ListLogRequestsResponse::default(), NOW),
            "No log requests from peers.\n"
        );
        let peer = quil_p2p::Keypair::falcon_from_bytes(&quil_p2p::generate_falcon_signing_key())
            .unwrap()
            .public()
            .to_peer_id();
        let mut from_peer = pending_request(0x11, LogRequestStatus::Served, Vec::new());
        from_peer.requester_peer_id = peer.to_bytes();
        let text = render_pending(
            &ListLogRequestsResponse {
                requests: vec![from_peer],
                ..Default::default()
            },
            NOW,
        );
        assert!(
            text.lines()
                .nth(2)
                .unwrap()
                .starts_with(&format!("11111111  {}  served", peer_tail(&peer))),
            "{text}"
        );
        assert!(
            !text.contains("Approve one"),
            "nothing waits for a decision"
        );
    }

    #[test]
    fn a_submitted_request_says_what_comes_next_and_a_refusal_why() {
        let mut response = SubmitLogRequestResponse {
            request_id: vec![0x3f; 16],
            expires_unix_ms: NOW + 86_400_000,
            ..Default::default()
        };
        response.set_status(LogRequestStatus::Pending);
        let id = "3f".repeat(16);
        assert_eq!(render_submitted("…Ab12cd", "QmTarget", 1_791_978_400, 1_792_000_000, 2, &response, NOW), format!("\
Asked …Ab12cd for lines of 2 shard filters of 2026-10-14T11:46:40Z .. 2026-10-14T17:46:40Z (UTC): request {id}.
It waits for …Ab12cd's operator, who sees a redacted preview before anything is sent; it expires in 24h unless approved.
Check it with: qclient node diagnostics status QmTarget 3f3f3f3f
Once approved, fetch it with: qclient node diagnostics fetch QmTarget 3f3f3f3f
"));
        response.automatic = true;
        assert_eq!(render_submitted("…Ab12cd", "QmTarget", 1_791_978_400, 1_792_000_000, 0, &response, NOW), format!("\
Asked …Ab12cd for every line of 2026-10-14T11:46:40Z .. 2026-10-14T17:46:40Z (UTC): request {id}.
…Ab12cd approves it itself, as its operator allows for this peer: it exports the window with 'node log export' redaction and seals it to this request's key, usually within minutes; it expires in 24h unless approved.
Check it with: qclient node diagnostics status QmTarget 3f3f3f3f
Once approved, fetch it with: qclient node diagnostics fetch QmTarget 3f3f3f3f
"));
        response.set_status(LogRequestStatus::Refused);
        response.set_refusal(LogRequestRefusal::OverBudget);
        assert_eq!(render_submitted("…Ab12cd", "QmTarget", 0, 1, 0, &response, NOW),
            "…Ab12cd refused log request 3f3f3f3f: this node used its requests for the last 24 h (diagnostics.logRequests.requestsPerDay).\n");
    }

    /// The target's budget follows the answer; a node of an earlier
    /// release reports none, and the answer reads as before.
    #[test]
    fn a_submitted_request_reports_the_targets_budget() {
        let mut response = SubmitLogRequestResponse {
            request_id: vec![0x3f; 16],
            expires_unix_ms: NOW + 86_400_000,
            ..Default::default()
        };
        response.set_status(LogRequestStatus::Pending);
        let older = render_submitted(
            "…Ab12cd",
            "QmTarget",
            1_791_978_400,
            1_792_000_000,
            0,
            &response,
            NOW,
        );
        assert!(
            !older.contains("Requests left") && !older.contains("Next request"),
            "{older}"
        );
        (
            response.requests_remaining,
            response.requests_per_day,
            response.next_request_unix_ms,
        ) = (Some(1), Some(2), Some(NOW + 86_400_000));
        let text = render_submitted(
            "…Ab12cd",
            "QmTarget",
            1_791_978_400,
            1_792_000_000,
            0,
            &response,
            NOW,
        );
        assert_eq!(
            text.lines().nth(2),
            Some("Requests left: 1 of 2 per 24 h."),
            "{text}"
        );
        assert!(
            text.lines().nth(3).unwrap().starts_with("Check it with:"),
            "no time while requests are left: {text}"
        );
        assert_eq!(
            text.replace("Requests left: 1 of 2 per 24 h.\n", ""),
            older,
            "the rest reads as before"
        );
        (response.requests_remaining, response.next_request_unix_ms) =
            (Some(0), Some(NOW + 86_400_000 - 1));
        let text = render_submitted(
            "…Ab12cd",
            "QmTarget",
            1_791_978_400,
            1_792_000_000,
            0,
            &response,
            NOW,
        );
        assert!(
            text.contains(
                "\
Requests left: 0 of 2 per 24 h.
Next request possible at 2026-10-15T17:46:40Z (UTC).
Check it with:"
            ),
            "{text}"
        );
        response.set_status(LogRequestStatus::Refused);
        response.set_refusal(LogRequestRefusal::OverBudget);
        assert_eq!(render_submitted("…Ab12cd", "QmTarget", 0, 1, 0, &response, NOW), "\
…Ab12cd refused log request 3f3f3f3f: this node used its requests for the last 24 h (diagnostics.logRequests.requestsPerDay).
Requests left: 0 of 2 per 24 h.
Next request possible at 2026-10-15T17:46:40Z (UTC).
");
        response.set_refusal(LogRequestRefusal::QueueFull);
        (
            response.requests_remaining,
            response.requests_per_day,
            response.next_request_unix_ms,
        ) = (Some(4), Some(4), None);
        assert_eq!(render_submitted("…Ab12cd", "QmTarget", 0, 1, 0, &response, NOW), "\
…Ab12cd refused log request 3f3f3f3f: its queue is full (diagnostics.logRequests.maxPending); ask again later.
Requests left: 4 of 4 per 24 h.
");
        (
            response.requests_remaining,
            response.requests_per_day,
            response.next_request_unix_ms,
        ) = (None, None, None);
        response.set_refusal(LogRequestRefusal::OverBudget);
        assert_eq!(render_submitted("…Ab12cd", "QmTarget", 0, 1, 0, &response, NOW),
            "…Ab12cd refused log request 3f3f3f3f: this node used its requests for the last 24 h (diagnostics.logRequests.requestsPerDay).\n",
            "a node of an earlier release reports no budget");
        (
            response.requests_remaining,
            response.requests_per_day,
            response.next_request_unix_ms,
        ) = (Some(0), Some(2), Some(u64::MAX));
        assert!(
            render_submitted("…Ab12cd", "QmTarget", 0, 1, 0, &response, NOW)
                .contains("Next request possible at "),
            "no overflow"
        );
    }

    #[test]
    fn a_status_names_the_next_step() {
        let denied = |denial: LogRequestDenial| {
            let mut response = LogRequestStatusResponse {
                request_id: vec![0x3f; 16],
                ..Default::default()
            };
            response.set_status(LogRequestStatus::Denied);
            response.set_denial(denial);
            render_status("…Ab12cd", "QmTarget", &response, NOW)
        };
        let status = |status: LogRequestStatus, bundle_bytes| {
            let mut response = LogRequestStatusResponse {
                request_id: vec![0x3f; 16],
                bundle_bytes,
                expires_unix_ms: NOW + 90 * 60_000,
                ..Default::default()
            };
            response.set_status(status);
            render_status("…Ab12cd", "QmTarget", &response, NOW)
        };
        assert_eq!(status(LogRequestStatus::Pending, 0),
            "Request 3f3f3f3f at …Ab12cd: pending: its node is exporting it, or its operator has yet to approve it; expires in 1h 30m.\n");
        assert_eq!(denied(LogRequestDenial::TooLarge), "\
Request 3f3f3f3f at …Ab12cd: denied by its node: the export exceeds its diagnostics.logRequests.maxBundleBytes; ask for a shorter window or fewer shard filters.
");
        assert_eq!(denied(LogRequestDenial::ExportFailed),
            "Request 3f3f3f3f at …Ab12cd: denied by its node: its export failed, for a reason its log names; ask again later.\n");
        assert_eq!(
            denied(LogRequestDenial::Operator),
            "Request 3f3f3f3f at …Ab12cd: denied by its operator.\n"
        );
        assert_eq!(
            status(LogRequestStatus::Ready, 2048),
            "\
Request 3f3f3f3f at …Ab12cd: approved, 2048 sealed bytes; fetchable for 1h 30m.
Fetch it with: qclient node diagnostics fetch QmTarget 3f3f3f3f
"
        );
        assert!(
            status(LogRequestStatus::Served, 2048).contains("2048 sealed bytes, fetched before;")
        );
        assert_eq!(
            status(LogRequestStatus::Denied, 0),
            "Request 3f3f3f3f at …Ab12cd: denied by its operator.\n"
        );
        assert_eq!(
            status(LogRequestStatus::Expired, 0),
            "Request 3f3f3f3f at …Ab12cd: expired before it was approved or fetched.\n"
        );
    }

    #[test]
    fn a_denied_call_names_what_the_target_operator_must_configure() {
        let denied = tonic::Status::permission_denied(quil_rpc::diagnostics_service::DENIED);
        assert_eq!(
            render_call_refusal("…Ab12cd", &denied, "QmOwnPeerId", "this node's"),
            "\
…Ab12cd refused the log request (diagnostics unavailable).
Its operator accepts requests only from peers listed in that node's config:
  diagnostics:
    logRequests:
      enabled: true
      allowedPeers:
        - QmOwnPeerId
and a restart of that node. QmOwnPeerId is this node's peer ID.
"
        );
        assert_eq!(
            render_call_refusal(
                "…Ab12cd",
                &tonic::Status::not_found("x"),
                "Qm",
                "this node's"
            ),
            "…Ab12cd knows no such log request from this node.\n"
        );
        assert!(render_call_refusal(
            "…Ab12cd",
            &tonic::Status::unimplemented(""),
            "Qm",
            "this node's"
        )
        .contains("predates"));
        let hostile = tonic::Status::internal(format!("bad\u{1b}[31m\nred{}", "x".repeat(500)));
        let text = render_call_refusal("…Ab12cd", &hostile, "Qm", "this identity's");
        assert!(
            !text.contains('\u{1b}') && text.matches('\n').count() == 1 && text.len() < 300,
            "{text}"
        );
    }

    #[test]
    fn windows_filters_and_ids_are_checked() {
        let now = 1_792_000_000;
        assert_eq!(
            parse_window("6h", None, now).unwrap(),
            (now as u64 - 6 * 3600, now as u64)
        );
        assert_eq!(
            parse_window("2026-10-14T00:00:00Z", Some("2026-10-14T01:00:00Z"), now).unwrap(),
            (1_791_936_000, 1_791_939_600)
        );
        assert!(parse_window("25h", None, now).is_err());
        assert!(parse_window("1h", Some("2h"), now).is_err());
        assert_eq!(
            parse_filters(&[format!("0x{}", "A1".repeat(32))]).unwrap(),
            [vec![0xa1; 32]]
        );
        assert_eq!(parse_filters(&["0b".repeat(64)]).unwrap(), [vec![0x0b; 64]]);
        for bad in [
            "zz".to_string(),
            String::new(),
            "abc".to_string(),
            "a1b2".to_string(),
            "aa".repeat(31),
            "aa".repeat(65),
        ] {
            assert!(parse_filters(&[bad.clone()]).is_err(), "{bad}");
        }
        assert!(parse_filters(&vec!["aa".repeat(32); 17])
            .unwrap_err()
            .to_string()
            .contains("at most 16"));
        let ids = [
            vec![0x3f; 16],
            vec![0x3e; 16],
            [vec![0x3f; 4], vec![0; 12]].concat(),
        ];
        assert_eq!(
            resolve_id(ids.iter().map(Vec::as_slice), "3e3e3e3e").unwrap(),
            vec![0x3e; 16]
        );
        assert!(resolve_id(ids.iter().map(Vec::as_slice), "3f3f3f3f")
            .unwrap_err()
            .to_string()
            .contains("names 2"));
        assert_eq!(
            resolve_id(ids.iter().map(Vec::as_slice), "3F3F3F3F3F").unwrap(),
            vec![0x3f; 16]
        );
        assert!(
            resolve_id(ids.iter().map(Vec::as_slice), "3f3f").is_err(),
            "too short"
        );
        assert!(resolve_id(ids.iter().map(Vec::as_slice), "00000000")
            .unwrap_err()
            .to_string()
            .contains("no log request"));
    }

    fn fixture_files() -> (Vec<u8>, String, String) {
        let log = b"\x1f\x8b gz bytes".to_vec();
        let manifest = "{\"lines\":{\"kept\":3}}\n".to_string();
        let sums = format!(
            "{}  {BUNDLE_LOG}\n{}  manifest.json\n",
            hex::encode(Sha256::digest(&log)),
            hex::encode(Sha256::digest(manifest.as_bytes()))
        );
        (log, manifest, sums)
    }

    /// A target's sealed fixture opens with the request's key alone and
    /// writes the export layout; a changed file or name is refused.
    #[test]
    fn a_fetched_bundle_opens_with_the_request_key_into_the_export_layout() {
        let (log, manifest, sums) = fixture_files();
        let plaintext = pack_bundle(&[
            (BUNDLE_LOG, &log),
            ("manifest.json", manifest.as_bytes()),
            ("SHA256SUMS", sums.as_bytes()),
        ]);
        let kem = quil_crypto::Sntrup761KeyPair::generate();
        let id = vec![0x3f; 16];
        let sealed = quil_crypto::seal::seal(&plaintext, &kem.public, &id).unwrap();
        let key = RequestKey {
            target: "QmTarget".into(),
            request_id: hex::encode(&id),
            kem_secret_key: hex::encode(&kem.secret),
            since_unix: 1,
            until_unix: 2,
        };
        let files = open_fetched(&sealed, &key).unwrap();
        assert_eq!(
            files,
            [
                log.clone(),
                manifest.as_bytes().to_vec(),
                sums.as_bytes().to_vec()
            ]
        );
        let other = RequestKey {
            kem_secret_key: hex::encode(quil_crypto::Sntrup761KeyPair::generate().secret),
            ..key.clone()
        };
        assert!(open_fetched(&sealed, &other).is_err());
        assert!(
            open_fetched(
                &sealed,
                &RequestKey {
                    request_id: "3e".repeat(16),
                    ..key.clone()
                }
            )
            .is_err(),
            "bound to its request"
        );

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("node-log-export-x");
        write_bundle(&out, &files).unwrap();
        for (name, data) in BUNDLE_FILES.iter().zip(&files) {
            assert_eq!(&std::fs::read(out.join(name)).unwrap(), data, "{name}");
        }
        assert!(write_bundle(&out, &files).is_err(), "never overwrites");
        assert!(!export::with_suffix(&out, ".partial").exists());

        let tampered = pack_bundle(&[
            (BUNDLE_LOG, b"other"),
            ("manifest.json", manifest.as_bytes()),
            ("SHA256SUMS", sums.as_bytes()),
        ]);
        assert!(unpack_bundle(&tampered)
            .unwrap_err()
            .to_string()
            .contains("SHA256SUMS"));
        let renamed = pack_bundle(&[
            ("../evil", &log),
            ("manifest.json", manifest.as_bytes()),
            ("SHA256SUMS", sums.as_bytes()),
        ]);
        assert!(unpack_bundle(&renamed).is_err());
        let mut trailing = plaintext.clone();
        trailing.push(0);
        assert!(unpack_bundle(&trailing).is_err());
        assert!(unpack_bundle(&plaintext[..plaintext.len() - 1]).is_err());
        assert!(unpack_bundle(b"QLOGEXP1\x03").is_err());
    }

    #[test]
    fn a_request_key_is_private_and_found_by_its_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = quil_p2p::Keypair::falcon_from_bytes(&quil_p2p::generate_falcon_signing_key())
            .unwrap()
            .public()
            .to_peer_id();
        let other = quil_p2p::Keypair::falcon_from_bytes(&quil_p2p::generate_falcon_signing_key())
            .unwrap()
            .public()
            .to_peer_id();
        let key = RequestKey {
            target: target.to_base58(),
            request_id: "3f".repeat(16),
            kem_secret_key: "00".into(),
            since_unix: 1,
            until_unix: 2,
        };
        let requests = dir.path().join("requests");
        let path = save_request_key(&requests, &key).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(path.parent().unwrap())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        let found = request_keys(&requests, &target);
        assert_eq!(found.len(), 1);
        assert_eq!(
            (found[0].1.clone(), found[0].2.clone()),
            (key, vec![0x3f; 16])
        );
        assert!(request_keys(&requests, &other).is_empty());
        let (id, held) = peer_request_id(&requests, &target, "3f3f3f3f").unwrap();
        assert_eq!((id, held.is_some()), (vec![0x3f; 16], true));
        let (id, held) = peer_request_id(&requests, &other, &"3e".repeat(16)).unwrap();
        assert_eq!(
            (id, held.is_none()),
            (vec![0x3e; 16], true),
            "a full ID without a key, for status"
        );
        assert!(peer_request_id(&requests, &other, "3e3e3e3e").is_err());
    }

    #[test]
    fn the_upload_names_its_request_once_and_covers_the_bundle() {
        let sealed: Vec<u8> = (0..(2 * logs::UPLOAD_CHUNK_BYTES + 5))
            .map(|i| i as u8)
            .collect();
        let chunks = upload_chunks(&[7; 16], &sealed);
        assert_eq!(chunks.len(), 3);
        assert_eq!(
            (chunks[0].request_id.as_slice(), chunks[0].total_bytes),
            ([7u8; 16].as_slice(), sealed.len() as u64)
        );
        assert_eq!(chunks[0].sha256, Sha256::digest(&sealed).to_vec());
        assert!(chunks[1..]
            .iter()
            .all(|c| c.request_id.is_empty() && c.sha256.is_empty()));
        assert_eq!(
            chunks
                .iter()
                .flat_map(|c| c.data.clone())
                .collect::<Vec<u8>>(),
            sealed
        );
        assert!(chunks
            .iter()
            .all(|c| c.encoded_len() <= logs::MAX_OPERATOR_MESSAGE_BYTES));
        let mut capped = Capped {
            data: Vec::new(),
            cap: 4,
        };
        assert!(capped.write_all(b"1234").is_ok());
        assert!(capped.write_all(b"5").is_err());
    }

    #[test]
    fn keygen_writes_a_private_identity_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asker.key");
        let peer = keygen(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let before = std::fs::read(&path).unwrap();
        assert!(keygen(&path)
            .unwrap_err()
            .to_string()
            .contains("never overwrites"));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "the identity is unchanged"
        );
        assert!(String::from_utf8_lossy(&before).starts_with("# qclient diagnostics identity"));
        let key = load_identity(&path).unwrap();
        assert_eq!(
            falcon_peer(&key).unwrap(),
            peer,
            "keygen prints the identity's peer ID"
        );
        assert_ne!(
            keygen(&dir.path().join("other.key")).unwrap(),
            peer,
            "each identity is fresh"
        );
        std::fs::write(dir.path().join("junk.key"), "# x\nnot hex\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.path().join("junk.key"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            assert!(load_identity(&dir.path().join("junk.key"))
                .unwrap_err()
                .to_string()
                .contains("not a diagnostics identity"));
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(load_identity(&path)
                .unwrap_err()
                .to_string()
                .contains("readable by others"));
        }
    }

    /// An identity requester reads no local node: the node loader is never
    /// called, and without --addr no address is looked up.
    #[tokio::test]
    async fn an_identity_requester_never_reaches_a_local_node() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("asker.key");
        let peer = keygen(&path).unwrap();
        let (who, node) =
            requester_with(Some(&path), || panic!("the local node was loaded")).unwrap();
        assert!(node.is_none());
        assert_eq!(
            (who.peer, who.whose, who.requests_dir.clone()),
            (
                peer,
                "this identity's",
                dir.path().join("asker.key.requests")
            )
        );
        let target = falcon_peer(&quil_p2p::generate_falcon_signing_key()).unwrap();
        let error = target_addr(None, &target, &who.peer, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("--addr"), "{error}");
        assert_eq!(
            target_addr(None, &target, &who.peer, Some("192.0.2.4:8340"))
                .await
                .unwrap(),
            "192.0.2.4:8340"
        );
        let missing = requester_with(None, || anyhow::bail!("no node config"))
            .err()
            .unwrap();
        assert!(format!("{missing:#}").contains("--identity"), "{missing:#}");
        assert!(
            requester_with(Some(&dir.path().join("absent.key")), || panic!(
                "fell back to the node"
            ))
            .is_err()
        );
    }

    /// The peer listener authenticates a keygen identity as its own peer ID
    /// and takes its signed request when that ID is allowlisted.
    #[tokio::test]
    async fn a_keygen_identity_is_admitted_as_its_peer_id() {
        use quil_rpc::diagnostics_logs::{LogRequestServer, LogRequests};
        let dir = tempfile::tempdir().unwrap();
        let (listed_path, unlisted_path) = (
            dir.path().join("listed.key"),
            dir.path().join("unlisted.key"),
        );
        let (listed, _) = (
            keygen(&listed_path).unwrap(),
            keygen(&unlisted_path).unwrap(),
        );
        let server_key = quil_p2p::generate_falcon_signing_key();
        let server_peer = falcon_peer(&server_key).unwrap();
        let config = quil_config::LogRequestsConfig {
            enabled: true,
            allowed_peers: vec![listed.to_base58()],
            ..Default::default()
        };
        let queue = std::sync::Arc::new(LogRequests::new(
            &config,
            server_peer,
            dir.path().join("spool"),
        ));
        let server = LogRequestServer::new(queue);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let accept = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (tx, key) = (tx.clone(), server_key.clone());
                tokio::spawn(async move {
                    if let Ok(stream) =
                        quil_rpc::pqnoise_channel::pq_server_handshake(tcp, &key).await
                    {
                        let _ = tx.send(Ok::<_, std::io::Error>(stream));
                    }
                });
            }
        });
        let serve = tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(tonic::service::interceptor::InterceptedService::new(
                    server.peer_service(),
                    quil_rpc::peer_auth_middleware::peer_auth_interceptor,
                ))
                .serve_with_incoming(futures::stream::unfold(rx, |mut rx| async move {
                    rx.recv().await.map(|item| (item, rx))
                })),
        );
        let submit = |path: PathBuf| {
            let addr = addr.clone();
            async move {
                let (who, _) =
                    requester_with(Some(&path), || panic!("the local node was loaded")).unwrap();
                let now = now_ms();
                let request = LogRequest {
                    schema: logs::REQUEST_SCHEMA,
                    target_peer_id: server_peer.to_bytes(),
                    requester_public_key: quil_crypto::falcon_public_from_signing_key(&who.key)
                        .unwrap(),
                    issued_unix_ms: now,
                    nonce: vec![1; logs::NONCE_LEN],
                    since_unix: now / 1000 - 3600,
                    until_unix: now / 1000,
                    filters: Vec::new(),
                    recipient_kem_public_key: quil_crypto::Sntrup761KeyPair::generate().public,
                };
                let mut client = logs::connect_log_peer(&addr, &who.key, server_peer)
                    .await
                    .unwrap();
                client
                    .submit_log_request(logs::sign_request(&request, &who.key).unwrap())
                    .await
            }
        };
        let queued = submit(listed_path).await.unwrap().into_inner();
        assert_eq!(queued.status(), LogRequestStatus::Pending);
        let refused = submit(unlisted_path).await.unwrap_err();
        assert_eq!(refused.code(), tonic::Code::PermissionDenied);
        accept.abort();
        serve.abort();
    }

    /// Every way to ask another node warns that it sees the requester's
    /// address; keygen says its key is no prover key.
    #[test]
    fn the_help_says_the_target_sees_the_requesters_address() {
        use clap::CommandFactory;
        #[derive(clap::Parser)]
        struct Node {
            #[command(subcommand)]
            command: super::super::diagnostics::DiagnosticsCommand,
        }
        #[derive(clap::Parser)]
        struct Top {
            #[command(subcommand)]
            command: IdentityCommand,
        }
        let help = |command: &mut clap::Command, name: &str| {
            let text = command
                .find_subcommand_mut(name)
                .unwrap()
                .render_long_help()
                .to_string();
            text.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .to_lowercase()
        };
        let mut node = Node::command();
        for name in ["health", "request"] {
            let text = help(&mut node, name);
            assert!(text.contains("the target sees the ip address you connect from; use a network you are willing to reveal"), "{name}: {text}");
            assert!(text.contains("--identity"), "{name}");
        }
        for name in ["status", "fetch"] {
            assert!(help(&mut node, name).contains("--identity"), "{name}");
        }
        let keygen = help(&mut Top::command(), "keygen");
        assert!(keygen.contains("it is not a prover key"), "{keygen}");
        assert!(
            keygen.contains("sees the ip address you connect from"),
            "{keygen}"
        );
    }

    /// A target's answer is checked, not trusted: a short or foreign
    /// request ID neither panics nor passes.
    #[test]
    fn a_hostile_answer_neither_panics_nor_passes() {
        let mut response = SubmitLogRequestResponse {
            request_id: vec![1, 2],
            ..Default::default()
        };
        response.set_status(LogRequestStatus::Refused);
        assert!(render_submitted("…Ab12cd", "Qm", 0, 1, 0, &response, NOW)
            .starts_with("…Ab12cd refused log request 0102:"));
        response.set_status(LogRequestStatus::Pending);
        response.request_id.clear();
        assert!(
            render_submitted("…Ab12cd", "Qm", u64::MAX, u64::MAX, 0, &response, NOW)
                .contains("an invalid window")
        );
        assert!(check_submitted(&[0x3f; 16], &response, "…Ab12cd")
            .unwrap_err()
            .to_string()
            .contains("another request"));
        response.request_id = vec![0x3f; 16];
        assert!(check_submitted(&[0x3f; 16], &response, "…Ab12cd").is_ok());
        let status = LogRequestStatusResponse {
            request_id: vec![9],
            ..Default::default()
        };
        assert!(render_status("…Ab12cd", "Qm", &status, NOW).starts_with("Request 09 at …Ab12cd"));
    }

    /// A denied or expired request's key goes: nothing is left to fetch.
    #[test]
    fn a_settled_request_drops_its_key() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("k.json");
        for status in [
            LogRequestStatus::Pending,
            LogRequestStatus::Ready,
            LogRequestStatus::Served,
        ] {
            std::fs::write(&key, b"{}").unwrap();
            assert_eq!(settle_key(status, Some(&key)), None, "{status:?}");
            assert!(key.exists(), "{status:?} keeps the key");
        }
        for status in [LogRequestStatus::Denied, LogRequestStatus::Expired] {
            std::fs::write(&key, b"{}").unwrap();
            assert!(settle_key(status, Some(&key)).is_some(), "{status:?}");
            assert!(!key.exists(), "{status:?} drops the key");
        }
        assert_eq!(settle_key(LogRequestStatus::Denied, None), None);
    }

    #[test]
    fn deny_says_whether_it_withdrew_a_bundle() {
        assert_eq!(
            render_denied(&pending_request(
                0x3f,
                LogRequestStatus::Pending,
                Vec::new()
            )),
            "Denied log request 3f3f3f3f from unknown.\n"
        );
        assert_eq!(render_denied(&pending_request(0x3f, LogRequestStatus::Ready, Vec::new())),
            "Withdrew the approved bundle of log request 3f3f3f3f from unknown (not fetched yet): this node deleted it.\n");
        assert!(
            render_denied(&pending_request(0x3f, LogRequestStatus::Served, Vec::new()))
                .contains("(fetched before)")
        );
    }

    /// Approve exports exactly what `node log export` exports for the same
    /// window and filters: the same selection and the same produce path.
    #[test]
    fn approve_exports_what_a_manual_export_of_the_window_does() {
        let dir = tempfile::tempdir().unwrap();
        let filter = "a1".repeat(32);
        let other = "b2".repeat(32);
        let line = |time: &str, level: &str, message: &str, fields: &str| {
            format!("2026-10-14T{time}Z\t{level}\tquil_node/src/main.rs:7\t{message}\t{fields}\n")
        };
        let master = [
            line(
                "11:00:00",
                "info",
                "before the window",
                &format!("{{\"filter\":\"{filter}\"}}"),
            ),
            line(
                "12:00:00",
                "info",
                "frame materialized",
                &format!("{{\"filter\":\"{filter}\",\"peer\":\"192.0.2.7:8336\"}}"),
            ),
            line(
                "12:30:00",
                "info",
                "frame materialized",
                &format!("{{\"filter\":\"{other}\"}}"),
            ),
            line(
                "13:00:00",
                "warn",
                "archive slow",
                "{\"source\":\"192.0.2.8:8340\"}",
            ),
            line(
                "13:30:00",
                "debug",
                "detail",
                &format!("{{\"filter\":\"{filter}\"}}"),
            ),
            line(
                "15:00:00",
                "info",
                "after the window",
                &format!("{{\"filter\":\"{filter}\"}}"),
            ),
        ]
        .concat();
        std::fs::write(dir.path().join("master.log"), master).unwrap();
        std::fs::write(
            dir.path().join("worker-1.log"),
            line(
                "12:15:00",
                "info",
                "proposal",
                &format!("{{\"filter\":\"{filter}\"}}"),
            ),
        )
        .unwrap();
        let (since, until) = (1_791_979_200u64, 1_791_986_400u64); // 12:00 .. 14:00 UTC
        let mut request = pending_request(0x3f, LogRequestStatus::Pending, vec![vec![0xa1; 32]]);
        (request.since_unix, request.until_unix) = (since, until);
        let salt = [7u8; 32];
        let readers = || log_export::file_readers(dir.path(), since as i64, until as i64).unwrap();
        let (approve_readers, names) = readers();
        let source = log_export::SourceInfo::Files(names);
        let selection =
            bundle::request_selection(request.since_unix, request.until_unix, &request.filters)
                .unwrap();
        let approved = bundle::request_export(
            approve_readers,
            None,
            &source,
            &selection,
            &request.request_id,
            "…Ab12cd",
            Approval::Operator,
            1 << 20,
            &log_export::ExportOptions {
                salt: Some(salt),
                ..Default::default()
            },
        )
        .unwrap();

        let args = export::ExportArgs {
            since: format_rfc3339_utc(since as i64),
            until: Some(format_rfc3339_utc(until as i64)),
            source: LogSource::Files,
            filters: vec![filter.clone()],
            matches: Vec::new(),
            level: None,
            keep_self: false,
            out: None,
        };
        let manual_selection = export::selection(&args, NOW as i64 / 1000).unwrap();
        let options = log_export::ExportOptions {
            salt: Some(salt),
            ..Default::default()
        };
        let manual = log_export::produce(
            readers().0,
            None,
            &source,
            &manual_selection,
            Vec::new(),
            &options,
        )
        .unwrap();

        assert_eq!(approved.out.data, manual.out, "the same redacted log");
        assert_eq!(approved.token_map, manual.token_map);
        assert_eq!(
            approved.stats.lines_kept, 4,
            "the window's filter lines and its warning, every level"
        );
        let mut approved_manifest = approved.manifest.clone();
        assert_eq!(
            approved_manifest["tool"],
            "qclient node diagnostics approve"
        );
        assert_eq!(approved_manifest["request"]["id"], "3f".repeat(16));
        assert_eq!(approved_manifest["request"]["approval"], "operator");
        let object = approved_manifest.as_object_mut().unwrap();
        object.remove("request");
        object.insert("tool".into(), manual.manifest["tool"].clone());
        assert_eq!(approved_manifest, manual.manifest);
        let preview = log_export::preview(
            &approved.manifest,
            &approved.stats,
            &destination(&request),
            Path::new("m.map.txt"),
        );
        assert!(
            preview.contains(&format!(
                "Shard filters (their lines, plus every warn and error line):\n  {filter}\n"
            )),
            "{preview}"
        );
    }

    #[test]
    fn an_approval_and_a_fetch_report_what_moved() {
        assert_eq!(render_approved("…Ab12cd", &[0x3f; 16], 4096, "24h", Path::new("/n/.diagnostics/token-maps/m.map.txt")), "\
Approved log request 3f3f3f3f of …Ab12cd: this node serves the 4096-byte sealed bundle to that peer alone, for 24h.
The token map /n/.diagnostics/token-maps/m.map.txt holds the original values: keep it private and never share it.
");
        assert_eq!(render_fetched("…Ab12cd", Path::new("node-log-export-x"), &[0x3f; 16], Some(12), 1_791_978_400, 1_792_000_000), "\
Wrote node-log-export-x (node.log.gz, manifest.json, SHA256SUMS): 12 redacted lines of …Ab12cd, 2026-10-14T11:46:40Z .. 2026-10-14T17:46:40Z (UTC), request 3f3f3f3f.
The request's key is deleted; …Ab12cd's operator keeps the token map.
");
    }
}
