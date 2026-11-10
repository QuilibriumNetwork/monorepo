//! gRPC client for connecting to a Quilibrium archive node's `GlobalService`.
//!
//! Archive nodes expose `GlobalService` over a TCP gRPC endpoint authenticated
//! with mTLS. The certificate scheme is unusual: each peer presents an
//! Ed25519 self-signed cert (since Go's x509 doesn't support Ed448) whose DNS
//! name field encodes a cross-signature linking it back to the peer's Ed448
//! identity. See `node/p2p/peer_authenticator.go` in the Go tree and the
//! `quil_tls` module here for the cert scheme.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::panic::Location;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use http::Uri;
use hyper_util::rt::TokioIo;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::transport::{Channel, Endpoint};
use tower::Service;
use tracing::{debug, info, warn};

use quil_types::proto::global::app_shard_service_client::AppShardServiceClient;
use quil_types::proto::global::global_service_client::GlobalServiceClient;
use quil_types::proto::global::{
    AppShardFrame, AppShardInfo, GetAppManifestRequest, GetAppShardFrameRequest,
    GetAppShardsRequest, GetForestHeadRequest, GetForestNodeRequest, GetForestPreimageRequest,
    GetForestValueRequest, GetGlobalFrameRequest, GetGlobalProposalRequest, GetVertexBlobRequest,
    GlobalFrame, GlobalProposal, ResolveRootRequest, SubmitGlobalConsensusRequest,
    SubmitGlobalMessageRequest,
};

use crate::quil_tls::{build_quil_tls_cert, QuilTlsError};

#[derive(Debug, Error)]
pub enum ArchiveClientError {
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("transport error: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("rpc error: {0}")]
    Rpc(#[from] tonic::Status),
    #[error("missing field in response: {0}")]
    MissingField(&'static str),
    #[error("tls cert error: {0}")]
    Tls(#[from] QuilTlsError),
    #[error("tls init error: {0}")]
    TlsInit(String),
}

/// The endpoint answered with this node's own identity: the mainnet archive
/// address list names every archive, this one included.
#[derive(Debug, Error)]
#[error("archive endpoint is this node")]
pub struct OwnEndpoint;

impl ArchiveClientError {
    /// The connection reached this node itself.
    pub fn is_own_endpoint(&self) -> bool {
        causes(self).any(|cause| cause.downcast_ref::<OwnEndpoint>().is_some())
    }

    /// The archive answered that its forest reads are busy.
    pub fn is_busy(&self) -> bool {
        matches!(self, Self::Rpc(status) if status.code() == tonic::Code::ResourceExhausted)
    }

    /// The request outran this client's per-request deadline, which tonic
    /// reports as `Cancelled` ("Timeout expired"): the archive took the
    /// request but did not answer in time.
    pub fn is_timeout(&self) -> bool {
        matches!(self, Self::Rpc(status) if status.code() == tonic::Code::Cancelled)
    }

    /// The archive lacks the call (an older build).
    pub fn is_unimplemented(&self) -> bool {
        matches!(self, Self::Rpc(status) if status.code() == tonic::Code::Unimplemented)
    }

    /// The request failed in the transport (the connection was closed, reset
    /// or went away), not with a status the archive sent. An archive closes
    /// connections a client leaves idle; such a request can go again at once
    /// on a fresh connection.
    pub fn is_transport_failure(&self) -> bool {
        causes(self).any(|cause| {
            cause.downcast_ref::<hyper::Error>().is_some()
                || cause.downcast_ref::<h2::Error>().is_some()
                || cause.downcast_ref::<std::io::Error>().is_some()
        })
    }

    /// The connection the call went over is no longer usable: the dial or
    /// the transport failed. A call that only outran its deadline leaves
    /// its connection usable.
    pub fn is_connection_failure(&self) -> bool {
        matches!(self, Self::Transport(_)) || self.is_transport_failure()
    }
}

/// `error` and every cause beneath it.
fn causes<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> impl Iterator<Item = &'a (dyn std::error::Error + 'static)> {
    std::iter::successors(Some(error), |error| error.source())
}

/// The causes beneath `error`, outermost first, separated by " -> ". A
/// transport failure reaches callers as "h2 protocol error: http2 error"; the
/// reason (a keepalive timeout, a reset or GOAWAY, an oversized frame) is only
/// in the source chain. Repeats of the text above are skipped.
pub fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut causes: Vec<String> = Vec::new();
    let mut above = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        if text != above && !above.contains(&text) {
            causes.push(text.clone());
        }
        above = text;
        source = cause.source();
    }
    causes.join(" -> ")
}

/// A connected gRPC client for an archive node's `GlobalService`.
///
/// `Clone` is cheap: the inner tonic client shares one multiplexed h2
/// `Channel`, so cached connections can be cloned per request (e.g. the
/// direct global-consensus publisher fanning to several archives).
#[derive(Clone)]
pub struct ArchiveClient {
    inner: GlobalServiceClient<Channel>,
    // AppShardService rides the SAME :8340 channel as GlobalService (both are
    // registered on the peer server); used by the state-jump to fetch attested
    // app-shard frames for onboarding root cross-checks.
    app_shard: AppShardServiceClient<Channel>,
    endpoint: String,
    /// Counts the connection as open until its last clone drops (PQNoise
    /// dials; [`ENDPOINT_CONNECTIONS_WARN`]).
    _open: Option<Arc<OpenConnection>>,
}

#[path = "archive_client_shared.rs"]
pub mod shared;

/// Where a dial was asked for: the caller of a `connect_*` function.
type Site = &'static Location<'static>;

/// This process's open connections plus dials in progress to one endpoint
/// above which it warns. A node keeps one or two connections per archive;
/// dozens mean a caller dials per request, which an archive's peer listener
/// refuses past its per-source cap for every node behind the same address.
const ENDPOINT_CONNECTIONS_WARN: usize = 32;

/// The warning repeats at most this often per endpoint while it lasts.
const ENDPOINT_LOAD_WARN_EVERY: Duration = Duration::from_secs(600);

/// Dials counted for the warning's rate, and the most remembered.
const DIAL_RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_DIALS_REMEMBERED: usize = 4096;

/// Call sites named in the warning.
const LOGGED_SITES: usize = 3;

/// One endpoint's connections from this process.
#[derive(Default)]
struct EndpointLoad {
    open: usize,
    dialing: usize,
    /// Dials started within [`DIAL_RATE_WINDOW`].
    dials: VecDeque<Instant>,
    /// Open plus dialing, by call site.
    sites: HashMap<Site, usize>,
    warned: Option<Instant>,
    over_since: Option<Instant>,
    peak: usize,
}

/// A line [`EndpointLoad::note`] asks for.
#[derive(Debug, PartialEq, Eq)]
enum LoadLine {
    Many {
        open: usize,
        dialing: usize,
        dials_last_60s: usize,
        sites: String,
    },
    Normal {
        open: usize,
        dialing: usize,
        peak: usize,
        secs: u64,
    },
}

impl EndpointLoad {
    /// Takes the counts after a change at `now`: a warning when open plus
    /// dialing passes [`ENDPOINT_CONNECTIONS_WARN`] (at most once per
    /// [`ENDPOINT_LOAD_WARN_EVERY`]), and one line once it falls back to
    /// half that.
    fn note(&mut self, now: Instant) -> Option<LoadLine> {
        while self
            .dials
            .front()
            .is_some_and(|at| now.saturating_duration_since(*at) > DIAL_RATE_WINDOW)
        {
            self.dials.pop_front();
        }
        let total = self.open + self.dialing;
        if total > ENDPOINT_CONNECTIONS_WARN {
            self.peak = self.peak.max(total);
            self.over_since.get_or_insert(now);
            if self
                .warned
                .is_some_and(|at| now.saturating_duration_since(at) < ENDPOINT_LOAD_WARN_EVERY)
            {
                return None;
            }
            self.warned = Some(now);
            let mut sites: Vec<(Site, usize)> = self
                .sites
                .iter()
                .filter(|(_, n)| **n > 0)
                .map(|(site, n)| (*site, *n))
                .collect();
            sites.sort_by(|a, b| {
                b.1.cmp(&a.1)
                    .then_with(|| (a.0.file(), a.0.line()).cmp(&(b.0.file(), b.0.line())))
            });
            let sites = sites
                .iter()
                .take(LOGGED_SITES)
                .map(|(site, n)| format!("{}:{}={n}", site.file(), site.line()))
                .collect::<Vec<_>>()
                .join(" ");
            return Some(LoadLine::Many {
                open: self.open,
                dialing: self.dialing,
                dials_last_60s: self.dials.len(),
                sites,
            });
        }
        if total <= ENDPOINT_CONNECTIONS_WARN / 2 {
            if let Some(since) = self.over_since.take() {
                return Some(LoadLine::Normal {
                    open: self.open,
                    dialing: self.dialing,
                    peak: std::mem::take(&mut self.peak),
                    secs: now.saturating_duration_since(since).as_secs(),
                });
            }
        }
        None
    }

    /// Nothing open, dialing or owed a line, and no warning left to pace.
    fn forgettable(&self, now: Instant) -> bool {
        self.open == 0
            && self.dialing == 0
            && self.over_since.is_none()
            && self
                .warned
                .is_none_or(|at| now.saturating_duration_since(at) >= ENDPOINT_LOAD_WARN_EVERY)
    }
}

static ENDPOINT_LOADS: std::sync::LazyLock<parking_lot::Mutex<HashMap<String, EndpointLoad>>> =
    std::sync::LazyLock::new(Default::default);

/// Apply `change` to `endpoint`'s load and log the line it asks for.
fn update_load(endpoint: &str, change: impl FnOnce(&mut EndpointLoad)) {
    let now = Instant::now();
    let line = {
        let mut loads = ENDPOINT_LOADS.lock();
        let load = loads.entry(endpoint.to_string()).or_default();
        change(load);
        let line = load.note(now);
        if load.forgettable(now) {
            loads.remove(endpoint);
        }
        line
    };
    match line {
        Some(LoadLine::Many {
            open,
            dialing,
            dials_last_60s,
            sites,
        }) => warn!(
            %endpoint,
            open,
            dialing,
            dials_last_60s,
            %sites,
            threshold = ENDPOINT_CONNECTIONS_WARN,
            action = "this node opens a connection per request to one archive; report this line",
            "many connections from this node to one archive endpoint (repeated every 10 min while it lasts)"
        ),
        Some(LoadLine::Normal {
            open,
            dialing,
            peak,
            secs,
        }) => info!(
            %endpoint,
            open,
            dialing,
            peak,
            secs,
            "connections from this node to one archive endpoint back to normal"
        ),
        None => {}
    }
}

/// A PQNoise dial in progress, counted for its endpoint and call site.
struct Dialing {
    endpoint: String,
    site: Site,
    done: bool,
}

impl Dialing {
    fn start(endpoint: &str, site: Site) -> Self {
        update_load(endpoint, |load| {
            load.dialing += 1;
            *load.sites.entry(site).or_default() += 1;
            load.dials.push_back(Instant::now());
            if load.dials.len() > MAX_DIALS_REMEMBERED {
                load.dials.pop_front();
            }
        });
        Self {
            endpoint: endpoint.to_string(),
            site,
            done: false,
        }
    }

    /// The dial connected: counted as open until the last clone drops.
    fn connected(mut self) -> Arc<OpenConnection> {
        self.done = true;
        update_load(&self.endpoint, |load| {
            load.dialing = load.dialing.saturating_sub(1);
            load.open += 1;
        });
        Arc::new(OpenConnection {
            endpoint: std::mem::take(&mut self.endpoint),
            site: self.site,
        })
    }
}

impl Drop for Dialing {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        let site = self.site;
        update_load(&self.endpoint, |load| {
            load.dialing = load.dialing.saturating_sub(1);
            if let Some(n) = load.sites.get_mut(site) {
                *n = n.saturating_sub(1);
            }
        });
    }
}

/// An open PQNoise connection, counted until its last client clone drops.
struct OpenConnection {
    endpoint: String,
    site: Site,
}

impl Drop for OpenConnection {
    fn drop(&mut self) {
        let site = self.site;
        update_load(&self.endpoint, |load| {
            load.open = load.open.saturating_sub(1);
            if let Some(n) = load.sites.get_mut(site) {
                *n = n.saturating_sub(1);
            }
        });
    }
}

/// `endpoint`'s open connections and dials in progress (tests).
#[cfg(test)]
fn endpoint_load(endpoint: &str) -> (usize, usize) {
    ENDPOINT_LOADS
        .lock()
        .get(endpoint)
        .map_or((0, 0), |load| (load.open, load.dialing))
}

/// Requests in flight at once on one shared submission connection; others
/// wait for a slot, never for another connection. An archive's peer
/// listener allows 256 streams per connection.
pub const SUBMISSIONS_IN_FLIGHT: usize = 64;

/// A shared connection nobody used for this long closes.
pub const SHARED_IDLE: Duration = Duration::from_secs(60);

/// A shared connection's key: the endpoint, the identity dialing it, and
/// whether it carries submissions over 32 KiB. Those (storage epoch proofs,
/// up to MBs) take a connection of their own, so a frame header or a
/// confirmation never waits behind one in the connection's flow-control
/// window.
#[derive(Clone, PartialEq, Eq, Hash)]
struct SharedKey {
    endpoint: String,
    identity: Vec<u8>,
    large: bool,
}

type SharedSet = shared::SharedConnections<SharedKey, ArchiveClient, ArchiveClientError>;

/// The connections this process shares with archives for submissions and
/// short reads, dialed and run on [`archive_io`], which lives as long as the
/// process, whichever runtime a caller is on.
fn shared_connections() -> &'static SharedSet {
    static SET: std::sync::OnceLock<SharedSet> = std::sync::OnceLock::new();
    SET.get_or_init(|| {
        shared::SharedConnections::new(
            SHARED_IDLE,
            Some(SUBMISSIONS_IN_FLIGHT),
            Some(archive_io().handle().clone()),
        )
    })
}

/// Why a submission over a shared connection failed.
#[derive(Debug)]
pub enum SharedSubmitError {
    /// No connection could be made; callers that waited on the same dial
    /// share its error.
    Dial(Arc<ArchiveClientError>),
    /// The submission failed on the connection.
    Submit(ArchiveClientError),
}

/// Failing connections per archive address. A node retries an archive
/// that refuses connections many times a minute, which logged one warning
/// per attempt (thousands an hour while an archive was down); each address
/// now logs one outage: its start, a repeat at most every
/// [`OUTAGE_LOG_EVERY`](quil_engine::outage::OUTAGE_LOG_EVERY) and its end.
static CONNECT_OUTAGES: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<String, quil_engine::outage::Outage>>,
> = std::sync::LazyLock::new(Default::default);

/// The identity each archive endpoint this node knows the peer of must
/// present: the mainnet genesis archives' static endpoints, and configured
/// endpoints that name their peer. A PQNoise dial to such an endpoint that
/// answers as anyone else fails, so neither the endpoint nor the network
/// path to it can stand in for the archive it names. Other endpoints dial
/// as before.
static ARCHIVE_PEERS: std::sync::LazyLock<
    std::sync::RwLock<std::collections::HashMap<String, quil_p2p::PeerId>>,
> = std::sync::LazyLock::new(Default::default);

/// Pin `endpoint` (`host:port`, as the pool dials it) to `peer`: every later
/// PQNoise dial to it must reach that identity. An endpoint already pinned
/// to another peer keeps that pin, which is returned: one archive's record
/// naming another archive's endpoint must not make that archive unreachable.
pub fn pin_archive_peer(
    endpoint: &str,
    peer: quil_p2p::PeerId,
) -> std::result::Result<(), quil_p2p::PeerId> {
    let mut pins = ARCHIVE_PEERS.write().unwrap_or_else(|e| e.into_inner());
    match pins.get(endpoint) {
        Some(held) if *held != peer => Err(*held),
        Some(_) => Ok(()),
        None => {
            pins.insert(endpoint.to_string(), peer);
            Ok(())
        }
    }
}

/// The identity pinned for `endpoint` ([`pin_archive_peer`]), if any.
pub fn pinned_archive_peer(endpoint: &str) -> Option<quil_p2p::PeerId> {
    ARCHIVE_PEERS
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(endpoint)
        .copied()
}

/// The (endpoint, pinned peer) pairs of a master's archive directory. At
/// most 32 endpoints of at most 512 bytes; `peer_ids` is empty (a master
/// that predates it: all unpinned) or parallel to them, each entry empty
/// (unpinned) or a peer id of at most 128 bytes. The error names what is
/// malformed.
pub fn archive_directory(
    response: quil_types::proto::global::GetArchiveEndpointsResponse,
) -> Result<Vec<(String, Option<quil_p2p::PeerId>)>, &'static str> {
    if response.endpoints.len() > 32
        || response
            .endpoints
            .iter()
            .any(|e| e.is_empty() || e.len() > 512)
        || !(response.peer_ids.is_empty() || response.peer_ids.len() == response.endpoints.len())
        || response.peer_ids.iter().any(|p| p.len() > 128)
    {
        return Err("invalid archive directory dimensions");
    }
    let mut peers = response.peer_ids.into_iter();
    response
        .endpoints
        .into_iter()
        .map(|endpoint| match peers.next().filter(|p| !p.is_empty()) {
            None => Ok((endpoint, None)),
            Some(bytes) => quil_p2p::PeerId::from_bytes(&bytes)
                .map(|peer| (endpoint, Some(peer)))
                .map_err(|_| "invalid archive directory peer id"),
        })
        .collect()
}

/// Record one connection attempt to `addr`; returns the transition to log.
fn connect_outage(addr: &str, ok: bool) -> Option<quil_engine::outage::OutageEvent> {
    let now = std::time::Instant::now();
    let mut outages = CONNECT_OUTAGES.lock().unwrap_or_else(|e| e.into_inner());
    if ok {
        outages.remove(addr)?.observe(now, true)
    } else {
        outages
            .entry(addr.to_string())
            .or_default()
            .observe(now, false)
    }
}

fn log_connect_outage(
    addr: &str,
    event: Option<quil_engine::outage::OutageEvent>,
    error_chain: &str,
) {
    use quil_engine::outage::OutageEvent;
    match event {
        Some(OutageEvent::Began) => {
            info!(%addr, error_chain, scope = "peer",
                warn_after_s = quil_engine::outage::OUTAGE_LOG_EVERY.as_secs(),
                action = "no action needed: retried until the archive accepts connections, \
                          and this node uses the other archives meanwhile; it warns if it \
                          lasts 10 min",
                "cannot connect to an archive; retrying")
        }
        Some(OutageEvent::Continues { secs, failures }) => {
            tracing::warn!(%addr, secs, failures, error_chain, scope = "peer",
                action = "if this warning names every archive, check this node's outbound \
                          connections, DNS and firewall; if it names one, that archive is down \
                          and this node uses the others: no action needed",
                "archive connection still failing")
        }
        Some(OutageEvent::Ended { secs, failures }) => {
            info!(%addr, secs, failures, "archive connection recovered")
        }
        None => {}
    }
}

/// How long one request on an mTLS (PQNoise) channel may run, from its start
/// to the answer's headers. Consensus and sync calls rely on it to give up on
/// an archive that stopped answering.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The longest [`submit_deadline`]: under the 120 s an archive's peer
/// listener allows one request, its body included.
pub const SUBMIT_DEADLINE_CAP: Duration = Duration::from_secs(100);

/// Bytes a submission may take one second longer for, beyond
/// [`REQUEST_TIMEOUT`]: 32 KiB/s to an archive still delivers it.
const SUBMIT_BYTES_PER_SECOND: usize = 32 << 10;

/// How long a submission of `bytes` bytes may take: [`REQUEST_TIMEOUT`] plus
/// a second per 32 KiB, at most [`SUBMIT_DEADLINE_CAP`]. A submission under
/// 32 KiB (a frame header, a join, a confirmation) keeps 15 s; a 0.54 MB
/// storage epoch proof gets 31 s, a 1.46 MB one 59 s.
pub fn submit_deadline(bytes: usize) -> Duration {
    REQUEST_TIMEOUT
        .saturating_add(Duration::from_secs(
            (bytes / SUBMIT_BYTES_PER_SECOND) as u64,
        ))
        .min(SUBMIT_DEADLINE_CAP)
}

/// The runtime that dials archives for callers on a current-thread runtime
/// and runs their channels' I/O. An in-process worker runs one: a
/// synchronous call on its thread stalls every task there, and a PQNoise
/// handshake stalled past the archive's 10 s deadline is dropped (the
/// worker sees "pqnoise: io: unexpected end of file"), as is a channel
/// that leaves the archive's keepalive pings unanswered past its timeout.
/// Started at the first such dial; it lives as long as the process.
fn archive_io() -> &'static tokio::runtime::Runtime {
    static RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("archive-io")
            .enable_all()
            .build()
            .expect("failed to create the archive I/O runtime")
    })
}

/// Whether a dial from here runs on [`archive_io`]: unless the caller's
/// runtime has threads of its own to run it.
fn dials_off_this_thread() -> bool {
    !matches!(
        tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()),
        Ok(tokio::runtime::RuntimeFlavor::MultiThread)
    )
}

/// A dial on [`archive_io`] ends with the caller that awaits it.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl ArchiveClient {
    /// Connect to an archive node at the given `host:port` over plaintext gRPC.
    /// Useful for local testing only — production archive nodes require mTLS.
    pub async fn connect_plaintext(addr: &str) -> Result<Self, ArchiveClientError> {
        let url = format!("http://{}", addr);
        let endpoint = Endpoint::from_shared(url)
            .map_err(|e| ArchiveClientError::InvalidEndpoint(e.to_string()))?
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .keep_alive_while_idle(true);
        debug!(%addr, "dialing archive node (plaintext)");
        let channel = endpoint.connect().await?;
        info!(%addr, "archive client connected");
        Ok(Self {
            // 64 MiB decode/encode limit (tonic defaults to 4 MiB). Full
            // global frames and app-shard size sets routinely exceed 4 MiB;
            // the default silently failed those RPCs. Matches the hypersync
            // client limits in `hypergraph_sync_probe`.
            inner: GlobalServiceClient::new(channel.clone())
                .max_decoding_message_size(64 * 1024 * 1024)
                .max_encoding_message_size(64 * 1024 * 1024),
            app_shard: AppShardServiceClient::new(channel)
                .max_decoding_message_size(64 * 1024 * 1024)
                .max_encoding_message_size(64 * 1024 * 1024),
            endpoint: addr.to_string(),
            _open: None,
        })
    }

    /// Connect to an archive node using Quilibrium's mTLS scheme. Builds a
    /// client cert from the given Ed448 seed and uses a custom rustls
    /// connector that accepts any server cert (Quilibrium peers self-sign;
    /// trust comes from the application-layer cross-signature in the SAN).
    #[track_caller]
    pub fn connect_mtls<'a>(
        addr: &'a str,
        falcon_signing_key: &'a [u8],
    ) -> impl Future<Output = Result<Self, ArchiveClientError>> + 'a {
        let site = Location::caller();
        Self::connect_pq(
            addr,
            QuilPqNoiseConnector::new(falcon_signing_key.to_vec()),
            site,
        )
    }

    /// [`Self::connect_mtls`] to another archive: an endpoint answering with
    /// this node's identity fails with [`ArchiveClientError::is_own_endpoint`].
    #[track_caller]
    pub fn connect_archive<'a>(
        addr: &'a str,
        falcon_signing_key: &'a [u8],
    ) -> impl Future<Output = Result<Self, ArchiveClientError>> + 'a {
        let site = Location::caller();
        async move {
            let own = quil_p2p::Keypair::falcon_from_bytes(falcon_signing_key)
                .map_err(|error| ArchiveClientError::TlsInit(format!("own identity: {error}")))?
                .public()
                .to_peer_id();
            let connector =
                QuilPqNoiseConnector::new(falcon_signing_key.to_vec()).refusing_peer(own);
            Self::connect_pq(addr, connector, site).await
        }
    }

    /// [`Self::connect_mtls`] to a node that must answer as `peer`: a dial
    /// to an endpoint taken from a peer's signed record, so that the
    /// record cannot name another node's address and have it answer for it.
    #[track_caller]
    pub fn connect_peer<'a>(
        addr: &'a str,
        falcon_signing_key: &'a [u8],
        peer: quil_p2p::PeerId,
    ) -> impl Future<Output = Result<Self, ArchiveClientError>> + 'a {
        let site = Location::caller();
        let connector =
            QuilPqNoiseConnector::new(falcon_signing_key.to_vec()).with_expected_peer(peer);
        Self::connect_pq(addr, connector, site)
    }

    /// Connect only to this worker's own master, which holds the same Falcon
    /// identity. Historical canonical frames and the archive directory rely
    /// on this pin; possession of an unrelated peer key is insufficient.
    #[track_caller]
    pub fn connect_own_master<'a>(
        addr: &'a str,
        falcon_signing_key: &'a [u8],
    ) -> impl Future<Output = Result<Self, ArchiveClientError>> + 'a {
        let site = Location::caller();
        async move {
            let connector =
                QuilPqNoiseConnector::to_own_master(falcon_signing_key.to_vec()).map_err(|e| *e)?;
            Self::connect_pq(addr, connector, site).await
        }
    }

    /// The connection to the archive at `addr` this process shares for
    /// submissions under 32 KiB and short reads, dialed as
    /// [`Self::connect_mtls`] dials; each request on it may run for
    /// [`REQUEST_TIMEOUT`]. Callers that find none wait on one dial. Hold the
    /// result for the call, and [`shared::Shared::discard`] it when the call
    /// fails in the transport ([`ArchiveClientError::is_connection_failure`]).
    #[track_caller]
    pub fn shared<'a>(
        addr: &'a str,
        falcon_signing_key: &'a [u8],
    ) -> impl Future<Output = Result<shared::Shared<Self>, Arc<ArchiveClientError>>> + 'a {
        let site = Location::caller();
        Self::shared_lane(addr, falcon_signing_key, false, site)
    }

    async fn shared_lane(
        addr: &str,
        falcon_signing_key: &[u8],
        large: bool,
        site: Site,
    ) -> Result<shared::Shared<Self>, Arc<ArchiveClientError>> {
        let key = SharedKey {
            endpoint: addr.to_string(),
            identity: falcon_signing_key.to_vec(),
            large,
        };
        shared_connections()
            .connect(&key, || {
                let connector =
                    QuilPqNoiseConnector::new(falcon_signing_key.to_vec()).pinned_for(addr);
                // A large submission sets its own deadline on each request,
                // at most this.
                let request_timeout = if large {
                    SUBMIT_DEADLINE_CAP
                } else {
                    REQUEST_TIMEOUT
                };
                Self::dial_pq(addr, connector, true, request_timeout, site)
            })
            .await
    }

    /// Submit `data` to the archive at `addr` over the connection this
    /// process shares with it, within [`submit_deadline`] for its size: a
    /// request carries its body, and a fixed 15 s cut a 0.54 MB storage
    /// epoch proof off below 36 KB/s to an archive. Submissions over 32 KiB
    /// share a second connection. At most [`SUBMISSIONS_IN_FLIGHT`] run on
    /// one connection at once; the rest wait for a slot within their
    /// deadline. Each submission used to dial its own connection, and a
    /// burst of them from one address hit the archive's per-source cap.
    #[track_caller]
    pub fn submit_shared<'a>(
        addr: &'a str,
        falcon_signing_key: &'a [u8],
        data: Vec<u8>,
    ) -> impl Future<Output = Result<(), SharedSubmitError>> + 'a {
        let site = Location::caller();
        async move {
            let deadline = submit_deadline(data.len());
            let large = deadline > REQUEST_TIMEOUT;
            let key = SharedKey {
                endpoint: addr.to_string(),
                identity: falcon_signing_key.to_vec(),
                large,
            };
            let permit = tokio::time::timeout(deadline, shared_connections().permit(&key))
                .await
                .map_err(|_| {
                    SharedSubmitError::Submit(ArchiveClientError::Rpc(
                        tonic::Status::deadline_exceeded(
                            "every submission slot on the shared connection stayed taken past the deadline",
                        ),
                    ))
                })?;
            let mut client = Self::shared_lane(addr, falcon_signing_key, large, site)
                .await
                .map_err(SharedSubmitError::Dial)?;
            let submitted = client.submit_global_message_within(data, deadline).await;
            drop(permit);
            if let Err(error) = &submitted {
                if error.is_connection_failure() {
                    client.discard();
                }
            }
            submitted.map_err(SharedSubmitError::Submit)
        }
    }

    async fn connect_pq(
        addr: &str,
        connector: QuilPqNoiseConnector,
        site: Site,
    ) -> Result<Self, ArchiveClientError> {
        Self::dial_pq(
            addr,
            connector.pinned_for(addr),
            dials_off_this_thread(),
            REQUEST_TIMEOUT,
            site,
        )
        .await
    }

    /// [`Self::connect_pq`], on [`archive_io`] when `off_thread`, else on
    /// the caller's runtime; each request on the channel may run for
    /// `request_timeout`. Counted for `site` while it dials and stays open
    /// ([`ENDPOINT_CONNECTIONS_WARN`]).
    async fn dial_pq(
        addr: &str,
        connector: QuilPqNoiseConnector,
        off_thread: bool,
        request_timeout: Duration,
        site: Site,
    ) -> Result<Self, ArchiveClientError> {
        // Note: scheme is `http://` — tonic's Endpoint refuses `https://`
        // unless its own `tls_config(...)` is set; we bypass that to install
        // our own PQNoise connector (no rustls/TLS on :8340 anymore).
        let url = format!("http://{}", addr);
        let endpoint = Endpoint::from_shared(url)
            .map_err(|e| ArchiveClientError::InvalidEndpoint(e.to_string()))?;
        let endpoint = crate::pqnoise_channel::peer_endpoint(endpoint)
            // 10s connect (was 3s). Over WAN with 200-300ms RTT
            // the TLS handshake plus Ed448 cross-signature
            // verification can routinely take 1.5-2.5s; a 3s
            // budget left no margin for a single congestion event
            // during the handshake. Matches the plaintext path's
            // 10s timeout.
            .connect_timeout(Duration::from_secs(10))
            .timeout(request_timeout)
            .tcp_nodelay(true)
            // Actively PING the peer every 10s. `keep_alive_while_idle(true)`
            // alone is a NO-OP in tonic unless an interval is set — without
            // this, an idle cached connection sends nothing, the peer's h2
            // keepalive (20s interval / 10s timeout on the :8340 server)
            // reaps it, and the next use forces a full reconnect + the
            // expensive Ed448 mTLS handshake. Pinging under the peer's reap
            // window keeps consensus/sync connections alive so they're
            // reused instead of re-handshaken.
            .http2_keep_alive_interval(Duration::from_secs(10))
            .keep_alive_while_idle(true);

        debug!(%addr, "dialing archive node (PQNoise)");
        let dialing = Dialing::start(addr, site);
        let dialed = if off_thread {
            // The channel's connection and buffer tasks run where they are
            // spawned: the dial spawns them, and the buffer task those of a
            // reconnect, all on `archive_io`.
            let mut dial = AbortOnDrop(
                archive_io().spawn(async move { endpoint.connect_with_connector(connector).await }),
            );
            match (&mut dial.0).await {
                Ok(dialed) => dialed,
                Err(error) => match error.try_into_panic() {
                    Ok(panic) => std::panic::resume_unwind(panic),
                    Err(error) => {
                        return Err(ArchiveClientError::TlsInit(format!(
                            "archive dial ended: {error}"
                        )))
                    }
                },
            }
        } else {
            endpoint.connect_with_connector(connector).await
        };
        let channel = match dialed {
            Ok(ch) => ch,
            Err(e) => {
                // Walk the std::error::Error source chain so the actual
                // failure (rustls / DNS / TCP refused / handshake)
                // appears in logs. Tonic's Display impl strips this.
                use std::error::Error as _;
                let mut chain = format!("{}", e);
                let mut src: Option<&(dyn std::error::Error + 'static)> = e.source();
                while let Some(s) = src {
                    chain.push_str(" -> ");
                    chain.push_str(&format!("{}", s));
                    src = s.source();
                }
                log_connect_outage(addr, connect_outage(addr, false), &chain);
                return Err(e.into());
            }
        };
        debug!(%addr, "archive client connected (mTLS)");
        log_connect_outage(addr, connect_outage(addr, true), "");
        let open = dialing.connected();
        Ok(Self {
            // 64 MiB decode/encode limit (tonic defaults to 4 MiB). Full
            // global frames and app-shard size sets routinely exceed 4 MiB;
            // the default silently failed those RPCs. Matches the hypersync
            // client limits in `hypergraph_sync_probe`.
            inner: GlobalServiceClient::new(channel.clone())
                .max_decoding_message_size(64 * 1024 * 1024)
                .max_encoding_message_size(64 * 1024 * 1024),
            app_shard: AppShardServiceClient::new(channel)
                .max_decoding_message_size(64 * 1024 * 1024)
                .max_encoding_message_size(64 * 1024 * 1024),
            endpoint: addr.to_string(),
            _open: Some(open),
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Submit a prover message (e.g. ProverJoin wrapped in MessageBundle)
    /// to the archive node for relay into the consensus pipeline.
    /// This is how Go nodes submit joins — via gRPC, not BlossomSub.
    pub async fn submit_global_message(&mut self, data: Vec<u8>) -> Result<(), ArchiveClientError> {
        self.inner
            .submit_global_message(SubmitGlobalMessageRequest { data })
            .await?;
        Ok(())
    }

    /// [`Self::submit_global_message`] within `deadline`, at most the
    /// channel's own request timeout; the archive is told it too.
    pub async fn submit_global_message_within(
        &mut self,
        data: Vec<u8>,
        deadline: Duration,
    ) -> Result<(), ArchiveClientError> {
        let mut request = tonic::Request::new(SubmitGlobalMessageRequest { data });
        request.set_timeout(deadline);
        self.inner.submit_global_message(request).await?;
        Ok(())
    }

    /// Deliver a global-consensus message (proposal / vote / timeout)
    /// point-to-point to a peer archive. `bitmask` is the original gossip
    /// topic (GLOBAL_FRAME or GLOBAL_CONSENSUS) so the receiver routes it
    /// through the matching handler. Global consensus uses this instead of
    /// gossip because a full-coverage proposal exceeds the gossip
    /// message-size ceiling.
    pub async fn submit_global_consensus(
        &mut self,
        bitmask: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<(), ArchiveClientError> {
        self.inner
            .submit_global_consensus(SubmitGlobalConsensusRequest { bitmask, data })
            .await?;
        Ok(())
    }

    pub async fn get_app_shards(
        &mut self,
        shard_key: Vec<u8>,
        prefix: Vec<u32>,
    ) -> Result<Vec<AppShardInfo>, ArchiveClientError> {
        let resp = self
            .inner
            .get_app_shards(GetAppShardsRequest { shard_key, prefix })
            .await?
            .into_inner();
        Ok(resp.info)
    }

    /// Forest sync: fetch one JMT node (`borsh(NodeKey)` → `borsh(Node)`) of a
    /// shard/phase tree. `None` if the peer has no such node. Drives the
    /// client-side Merkle diff (see [`crate::forest_sync_reader::RemoteTreeReader`]).
    pub async fn get_forest_node(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
        node_key: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, ArchiveClientError> {
        let resp = self
            .inner
            .get_forest_node(GetForestNodeRequest {
                shard_id,
                phase,
                node_key,
            })
            .await?
            .into_inner();
        Ok(resp.found.then_some(resp.node))
    }

    /// Forest sync, batched: many JMT nodes of one shard/phase tree in one
    /// request. The answer covers a prefix of `node_keys`, in order (the
    /// archive stops at its size budget); `None` per absent node.
    pub async fn get_forest_nodes(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
        node_keys: Vec<Vec<u8>>,
    ) -> Result<Vec<Option<Vec<u8>>>, ArchiveClientError> {
        let resp = self
            .inner
            .get_forest_nodes(quil_types::proto::global::GetForestNodesRequest {
                shard_id,
                phase,
                node_keys,
            })
            .await?
            .into_inner();
        Ok(resp
            .nodes
            .into_iter()
            .map(|n| n.found.then_some(n.data))
            .collect())
    }

    /// Forest sync, batched: leaf values `(version, key_hash)` of one
    /// shard/phase tree. A prefix of the keys, in order, as for nodes.
    pub async fn get_forest_values(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
        keys: Vec<(u64, Vec<u8>)>,
    ) -> Result<Vec<Option<Vec<u8>>>, ArchiveClientError> {
        let keys = keys
            .into_iter()
            .map(
                |(version, key_hash)| quil_types::proto::global::ForestValueKey {
                    version,
                    key_hash,
                },
            )
            .collect();
        let resp = self
            .inner
            .get_forest_values(quil_types::proto::global::GetForestValuesRequest {
                shard_id,
                phase,
                keys,
            })
            .await?
            .into_inner();
        Ok(resp
            .values
            .into_iter()
            .map(|v| v.found.then_some(v.data))
            .collect())
    }

    /// Forest sync, batched: vertex blobs `(id, version)` under one app
    /// ShardKey, each read as of its tree version. A prefix, in order.
    pub async fn get_vertex_blobs(
        &mut self,
        shard_key: Vec<u8>,
        phase: u32,
        blobs: Vec<(Vec<u8>, u64)>,
    ) -> Result<Vec<Option<Vec<u8>>>, ArchiveClientError> {
        let blobs = blobs
            .into_iter()
            .map(|(id, version)| quil_types::proto::global::VertexBlobKey { id, version })
            .collect();
        let resp = self
            .inner
            .get_vertex_blobs(quil_types::proto::global::GetVertexBlobsRequest {
                shard_key,
                phase,
                blobs,
            })
            .await?
            .into_inner();
        Ok(resp
            .blobs
            .into_iter()
            .map(|b| b.found.then_some(b.data))
            .collect())
    }

    /// Forest sync, listed: leaves of one shard/phase tree with keys in
    /// `[first, last]` after `after`, each at its newest value at or below
    /// `version`, in key order, and whether more may follow.
    pub async fn get_forest_leaves(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
        version: u64,
        first: [u8; 32],
        last: [u8; 32],
        after: Option<[u8; 32]>,
    ) -> Result<(Vec<([u8; 32], Vec<u8>)>, bool), ArchiveClientError> {
        let resp = self
            .inner
            .get_forest_leaves(quil_types::proto::global::GetForestLeavesRequest {
                shard_id,
                phase,
                version,
                first: first.to_vec(),
                last: last.to_vec(),
                after: after.map(|key| key.to_vec()).unwrap_or_default(),
            })
            .await?
            .into_inner();
        let leaves = resp
            .leaves
            .into_iter()
            .map(|leaf| {
                <[u8; 32]>::try_from(leaf.key_hash.as_slice())
                    .map(|key| (key, leaf.value))
                    .map_err(|_| {
                        ArchiveClientError::MissingField("forest leaf key must be 32 bytes")
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((leaves, resp.more))
    }

    /// Forest sync: fetch a leaf value by `key_hash` (32 bytes) at `version`.
    pub async fn get_forest_value(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
        version: u64,
        key_hash: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, ArchiveClientError> {
        let resp = self
            .inner
            .get_forest_value(GetForestValueRequest {
                shard_id,
                phase,
                version,
                key_hash,
            })
            .await?
            .into_inner();
        Ok(resp.found.then_some(resp.value))
    }

    /// Forest sync: the peer's head `(version, root)` for a shard/phase tree, so
    /// the client can verify the root and diff at that version. `None` if the
    /// peer never committed the tree.
    pub async fn get_forest_head(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
    ) -> Result<Option<(u64, Vec<u8>)>, ArchiveClientError> {
        let resp = self
            .inner
            .get_forest_head(GetForestHeadRequest { shard_id, phase })
            .await?
            .into_inner();
        Ok(resp.found.then_some((resp.version, resp.root)))
    }

    /// Forest sync: the raw l3 key (`vertex_id ‖ field_key`) a diff's `key_hash`
    /// was committed from, so the client learns which vertices changed.
    pub async fn get_forest_preimage(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
        key_hash: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, ArchiveClientError> {
        let resp = self
            .inner
            .get_forest_preimage(GetForestPreimageRequest {
                shard_id,
                phase,
                key_hash,
            })
            .await?
            .into_inner();
        Ok(resp.found.then_some(resp.raw_key))
    }

    /// Forest sync: a changed vertex's committed blob (the readable data).
    /// `shard_key` is the app ShardKey bytes (`l1[3] ‖ l2[32]`).
    pub async fn get_vertex_blob(
        &mut self,
        shard_key: Vec<u8>,
        phase: u32,
        id: Vec<u8>,
        version: u64,
    ) -> Result<Option<Vec<u8>>, ArchiveClientError> {
        // `version` MVCC-pins the read to the tree version the diff addressed, so
        // the served blob matches the committed `commitment‖size` the sync just
        // applied. `0` ⇒ latest (immutable content-addressed vertices are safe at
        // latest; MUTABLE vertices — e.g. the 0xff prover shard's reward balances
        // and registry — MUST pin, else the archive serves a newer blob whose
        // leaf value no longer matches the diff → "peer served unbound data").
        let resp = self
            .inner
            .get_vertex_blob(GetVertexBlobRequest {
                shard_key,
                phase,
                id,
                version,
                exact_version: false,
            })
            .await?
            .into_inner();
        Ok(resp.found.then_some(resp.blob))
    }

    /// Ask this worker's authenticated master for its verified archive pool.
    pub async fn get_archive_endpoints(&mut self) -> Result<Vec<String>, ArchiveClientError> {
        Ok(self
            .get_archive_directory()
            .await?
            .into_iter()
            .map(|(endpoint, _)| endpoint)
            .collect())
    }

    /// [`get_archive_endpoints`](Self::get_archive_endpoints) with the peer
    /// the master pinned each endpoint to, if any.
    pub async fn get_archive_directory(
        &mut self,
    ) -> Result<Vec<(String, Option<quil_p2p::PeerId>)>, ArchiveClientError> {
        let response = self
            .inner
            .clone()
            .max_decoding_message_size(32 * (515 + 131) + 128)
            .get_archive_endpoints(quil_types::proto::global::GetArchiveEndpointsRequest {})
            .await?
            .into_inner();
        archive_directory(response).map_err(|why| tonic::Status::data_loss(why).into())
    }

    /// Fetch and authenticate one bounded historical GLOBAL membership proof.
    pub async fn get_global_vertex_proof(
        &mut self,
        root: [u8; 32],
        address: [u8; 32],
        allow_forward: bool,
    ) -> Result<Option<Vec<u8>>, ArchiveClientError> {
        let response = self
            .inner
            .clone()
            .max_decoding_message_size(
                quil_engine::storage_history::MAX_GLOBAL_VERTEX_PROOF_BYTES + 128,
            )
            .get_global_vertex_proof(quil_types::proto::global::GetGlobalVertexProofRequest {
                root: root.to_vec(),
                address: address.to_vec(),
                allow_forward,
            })
            .await?
            .into_inner();
        if !response.found {
            return Ok(None);
        }
        quil_engine::storage_history::verify_global_vertex_proof(&root, &address, &response.proof)
            .map_err(|e| tonic::Status::data_loss(e.to_string()))?;
        Ok(Some(response.proof))
    }

    /// Read the blob at an exact tree version, including the first version (0).
    pub async fn get_vertex_blob_at(
        &mut self,
        shard_key: Vec<u8>,
        phase: u32,
        id: Vec<u8>,
        version: u64,
    ) -> Result<Option<Vec<u8>>, ArchiveClientError> {
        let resp = self
            .inner
            .get_vertex_blob(GetVertexBlobRequest {
                shard_key,
                phase,
                id,
                version,
                exact_version: true,
            })
            .await?
            .into_inner();
        Ok(resp.found.then_some(resp.blob))
    }

    /// Peer coin scan over the same authenticated :8340 channel: ask a node
    /// that covers `domain` for one page of up to `max_coins` coins (a peer
    /// without the field answers eight). `Unavailable` means that peer does
    /// not serve the application — try the next one, not an empty answer.
    pub async fn list_shard_coins(
        &mut self,
        domain: Vec<u8>,
        snapshot_id: Vec<u8>,
        after: Vec<u8>,
        max_coins: u32,
    ) -> Result<quil_types::proto::global::ListShardCoinsResponse, ArchiveClientError> {
        Ok(self
            .app_shard
            .list_shard_coins(quil_types::proto::global::ListShardCoinsRequest {
                domain,
                snapshot_id,
                after,
                max_coins,
            })
            .await?
            .into_inner())
    }

    pub async fn list_shard_legacy_coins(
        &mut self,
        domain: Vec<u8>,
        owner: Vec<u8>,
        after: Vec<u8>,
    ) -> Result<quil_types::proto::global::ListLegacyCoinsResponse, ArchiveClientError> {
        Ok(self
            .app_shard
            .list_shard_legacy_coins(quil_types::proto::global::ListLegacyCoinsRequest {
                domain,
                owner,
                after,
            })
            .await?
            .into_inner())
    }

    pub async fn list_shard_escrows(
        &mut self,
        domain: Vec<u8>,
        snapshot_id: Vec<u8>,
        after: Vec<u8>,
        max_escrows: u32,
    ) -> Result<quil_types::proto::global::ListShardEscrowsResponse, ArchiveClientError> {
        Ok(self
            .app_shard
            .list_shard_escrows(quil_types::proto::global::ListShardCoinsRequest {
                domain,
                snapshot_id,
                after,
                max_coins: max_escrows,
            })
            .await?
            .into_inner())
    }

    /// A wallet vertex read with application coverage and worker-store routing.
    /// Do not substitute a forest-sync read of the peer's master store.
    pub async fn get_shard_vertex(
        &mut self,
        address: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, ArchiveClientError> {
        let vertex = self
            .app_shard
            .get_shard_vertex(quil_types::proto::global::GetShardVertexRequest { address })
            .await?
            .into_inner();
        Ok(vertex.found.then_some(vertex.blob))
    }

    /// Peer coin witnesses over the same authenticated channel: the membership
    /// paths a wallet needs to spend coins on an application this node does
    /// not cover.
    pub async fn get_shard_coin_witnesses(
        &mut self,
        domain: Vec<u8>,
        addresses: Vec<Vec<u8>>,
    ) -> Result<quil_types::proto::global::GetShardCoinWitnessesResponse, ArchiveClientError> {
        Ok(self
            .app_shard
            .get_shard_coin_witnesses(quil_types::proto::global::GetShardCoinWitnessesRequest {
                domain,
                addresses,
            })
            .await?
            .into_inner())
    }

    /// Sync-by-hash: translate an authenticated tree `root` to the serving
    /// peer's local `(version, global_frame)`. `None` ⇒ that peer never
    /// committed this root (behind) or pruned it; the caller then fails over
    /// to another peer or a full snapshot sync.
    pub async fn resolve_root(
        &mut self,
        shard_id: Vec<u8>,
        phase: u32,
        root: Vec<u8>,
    ) -> Result<Option<(u64, u64)>, ArchiveClientError> {
        let resp = self
            .inner
            .resolve_root(ResolveRootRequest {
                shard_id,
                phase,
                root,
            })
            .await?
            .into_inner();
        Ok(resp.found.then_some((resp.version, resp.global_frame)))
    }

    /// Sync-by-hash (split apps): the manifest of sub-shards that fold into an
    /// aggregate `app_root`: `[(prefix_words, sub_root, sub_version)]`. The
    /// caller MUST verify these aggregate back to the authenticated `app_root`
    /// before trusting any sub-root. `None` ⇒ not a known aggregate root here.
    #[allow(clippy::type_complexity)]
    pub async fn get_app_manifest(
        &mut self,
        app_address: Vec<u8>,
        phase: u32,
        app_root: Vec<u8>,
    ) -> Result<Option<Vec<(Vec<u8>, Vec<u8>, u64)>>, ArchiveClientError> {
        let resp = self
            .inner
            .get_app_manifest(GetAppManifestRequest {
                app_address,
                phase,
                app_root,
            })
            .await?
            .into_inner();
        if !resp.found {
            return Ok(None);
        }
        Ok(Some(
            resp.entries
                .into_iter()
                .map(|e| (e.prefix, e.root, e.version))
                .collect(),
        ))
    }

    /// Fetch a single global frame. Pass `frame_number = 0` to request the
    /// latest finalized frame.
    pub async fn get_global_frame(
        &mut self,
        frame_number: u64,
    ) -> Result<GlobalFrame, ArchiveClientError> {
        let resp = self
            .inner
            .get_global_frame(GetGlobalFrameRequest {
                frame_number,
                historical_anchor: false,
                header_only: false,
                if_newer_than: 0,
            })
            .await?
            .into_inner();
        resp.frame.ok_or(ArchiveClientError::MissingField("frame"))
    }

    /// GLOBAL frame `frame_number` as its header alone, for a caller that
    /// checks headers and their links and never reads the request bundles,
    /// which can make a frame megabytes long. A server that predates the
    /// `header_only` flag sends the whole frame; its bundles are dropped
    /// here, so the answer is the same either way.
    pub async fn get_global_frame_header_only(
        &mut self,
        frame_number: u64,
    ) -> Result<GlobalFrame, ArchiveClientError> {
        let resp = self
            .inner
            .get_global_frame(GetGlobalFrameRequest {
                frame_number,
                historical_anchor: false,
                header_only: true,
                if_newer_than: 0,
            })
            .await?
            .into_inner();
        let mut frame = resp
            .frame
            .ok_or(ArchiveClientError::MissingField("frame"))?;
        frame.requests.clear();
        Ok(frame)
    }

    /// The latest GLOBAL frame for a poller that holds frames up to
    /// `newer_than`: whole when the archive's head is newer, else its header
    /// alone, which gives the archive's height without the request bundles
    /// the poller already holds. A server that predates `if_newer_than`
    /// sends the whole head either way; `0` asks for it whole.
    pub async fn get_global_head(
        &mut self,
        newer_than: u64,
    ) -> Result<GlobalFrame, ArchiveClientError> {
        let resp = self
            .inner
            .get_global_frame(GetGlobalFrameRequest {
                frame_number: 0,
                if_newer_than: newer_than,
                ..Default::default()
            })
            .await?
            .into_inner();
        resp.frame.ok_or(ArchiveClientError::MissingField("frame"))
    }

    /// Historical GLOBAL frame `frame_number` from this worker's own master
    /// (see [`Self::connect_own_master`]), which needs only its header: the
    /// master serves it even when it pruned the frame's request bodies, and
    /// fetches an authenticated copy from an archive when it never held it.
    /// Any other server treats this as [`Self::get_global_frame`].
    pub async fn get_global_anchor(
        &mut self,
        frame_number: u64,
    ) -> Result<GlobalFrame, ArchiveClientError> {
        let resp = self
            .inner
            .get_global_frame(GetGlobalFrameRequest {
                frame_number,
                historical_anchor: true,
                header_only: false,
                if_newer_than: 0,
            })
            .await?
            .into_inner();
        resp.frame.ok_or(ArchiveClientError::MissingField("frame"))
    }

    /// Fetch the full proposal (state + parent QC + prior TC + vote) for
    /// `frame_number`, so a lagging node can submit it into its consensus loop
    /// to catch up. The server returns an empty response (no proposal) on a
    /// lookup miss, which surfaces here as `MissingField`.
    pub async fn get_global_proposal(
        &mut self,
        frame_number: u64,
    ) -> Result<GlobalProposal, ArchiveClientError> {
        let resp = self
            .inner
            .get_global_proposal(GetGlobalProposalRequest { frame_number })
            .await?
            .into_inner();
        resp.proposal
            .ok_or(ArchiveClientError::MissingField("proposal"))
    }

    /// Fetch a committed app-shard frame by its consensus `filter` (the app's
    /// `L2 ‖ prefix` address; QUIL's per-app consensus uses the 32-byte L2).
    /// `frame_number == 0` asks the peer for its LATEST frame on that filter.
    /// The returned `FrameHeader.state_roots[0]` is the app's aggregate
    /// vertex-adds root — the state-jump onboarding path cross-checks the
    /// locally-synced app tree against it. `None` if the peer has no frame.
    pub async fn get_app_shard_frame(
        &mut self,
        filter: Vec<u8>,
        frame_number: u64,
    ) -> Result<Option<AppShardFrame>, ArchiveClientError> {
        let resp = self
            .app_shard
            .get_app_shard_frame(GetAppShardFrameRequest {
                filter,
                frame_number,
            })
            .await?
            .into_inner();
        Ok(resp.frame)
    }

    /// One page of `filter`'s recorded outgoing records from `from_frame`:
    /// contiguous and ascending, possibly shorter than requested. Unverified:
    /// the caller authenticates it against a certified history root.
    pub async fn get_shard_outgoing_history(
        &mut self,
        filter: Vec<u8>,
        from_frame: u64,
        through_frame: u64,
    ) -> Result<Vec<quil_types::proto::global::ShardFrameOutgoing>, ArchiveClientError> {
        let frames = self
            .app_shard
            .clone()
            .max_decoding_message_size(crate::stub_services::MAX_OUTGOING_HISTORY_BYTES * 2)
            .get_shard_outgoing_history(quil_types::proto::global::GetShardOutgoingHistoryRequest {
                filter,
                from_frame,
                through_frame,
            })
            .await?
            .into_inner()
            .frames;
        if frames
            .iter()
            .enumerate()
            .any(|(i, f)| f.frame_number != from_frame + i as u64)
        {
            return Err(tonic::Status::data_loss(
                "outgoing history page is not contiguous from the requested frame",
            )
            .into());
        }
        Ok(frames)
    }
}

/// rustls verifier for archive server certs. Quilibrium peers
/// self-sign with Ed25519-derived keys, so the standard PKI path
/// can't be used — but we are NOT "accept any cert". Trust is
/// established at the application layer via the Ed448 xsign
/// cross-signature embedded in the cert's SAN DNS name. The
/// previous implementation accepted ANY syntactically-valid cert
/// here, which (combined with PeerInfo gossip carrying an
/// attacker-controlled peer_id) opened a genesis-archive
/// impersonation path: a malicious peer could advertise an archive
/// capability under any peer_id and pass the mTLS handshake with
/// their own unrelated cert.
///
/// This verifier now runs the same xsign verification that the
/// server-side [`crate::quil_tls::XsignClientCertVerifier`] applies
/// to client certs — proving the cert's SAN really was issued by
/// the Ed448 key it claims. Pairing each archive_pool entry with
/// its expected peer_id (so a mismatch between the certificate's
/// xsign-derived Ed448 pubkey and the expected genesis-archive
/// identity could be rejected) is a useful next-layer hardening
/// but requires plumbing the expected peer_id through the pool +
/// poller call chain. Today the PeerInfo signature check
/// (`validator_global_peer_info` in `quil-engine`) already ensures
/// nobody can publish a PeerInfo claiming the genesis-archive
/// peer_id without holding its Ed448 signing key, so the
/// impersonation chain is already broken at the gossip layer.
#[derive(Debug)]
pub struct AcceptAnyServerCert {
    /// Signature-verification algorithms from the installed crypto provider,
    /// used to perform the real TLS `CertificateVerify` proof-of-possession
    /// check in `verify_tls1x_signature`.
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl Default for AcceptAnyServerCert {
    /// Build a verifier wired to the ring crypto provider's signature
    /// algorithms (matching the provider installed by
    /// `build_quil_client_config`).
    fn default() -> Self {
        Self {
            supported: rustls::crypto::ring::default_provider().signature_verification_algorithms,
        }
    }
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // Apply the Quilibrium xsign check to the presented cert.
        // Identical to the server-side client-auth verifier — the
        // mTLS handshake is symmetric: each side proves SAN-derived
        // identity to the other.
        crate::quil_tls::XsignClientCertVerifier::verify_xsign(end_entity.as_ref())?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // This callback IS the TLS proof-of-possession check: verify the
        // server's CertificateVerify signature against the cert's Ed25519 key,
        // proving the live server holds the cert's private half. Without it a
        // replayed (public) peer cert would be accepted from any party.
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // The Quilibrium cert always uses Ed25519 — narrow the list so
        // rustls negotiates that scheme. (The Go side leaves it open;
        // restricting here is harmless and surfaces mismatches early.)
        // Mirrors the server-side `XsignClientCertVerifier`.
        vec![SignatureScheme::ED25519]
    }
}

/// Build a rustls `ClientConfig` that presents a Quilibrium peer cert and
/// accepts any server cert. Suitable for `tonic`'s tls layer when paired with
/// a custom transport.
/// Process-wide cache of built client TLS configs, keyed by Ed448 seed.
/// The config is a pure, deterministic function of the seed — same seed
/// always yields the identical cert + cross-signature — but building it
/// runs a (slow, vendored-pure-Rust) Ed448 public-key derivation + Ed448
/// SIGN plus x509 cert generation. Recomputing that on every `connect_mtls`
/// put an Ed448 signature on the critical path of every outbound dial
/// (thousands per node under reconnect churn), starving the `:8340`
/// handshake path that consensus delivery depends on. Build once, reuse.
static CLIENT_CONFIG_CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<Vec<u8>, Arc<ClientConfig>>>,
> = std::sync::OnceLock::new();

pub fn build_quil_client_config(
    falcon_signing_key: &[u8],
) -> Result<Arc<ClientConfig>, ArchiveClientError> {
    let cache =
        CLIENT_CONFIG_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Some(cfg) = cache.lock().unwrap().get(falcon_signing_key) {
        return Ok(cfg.clone());
    }
    let cfg = build_quil_client_config_uncached(falcon_signing_key)?;
    cache
        .lock()
        .unwrap()
        .insert(falcon_signing_key.to_vec(), cfg.clone());
    Ok(cfg)
}

fn build_quil_client_config_uncached(
    falcon_signing_key: &[u8],
) -> Result<Arc<ClientConfig>, ArchiveClientError> {
    let tls_cert = build_quil_tls_cert(falcon_signing_key)?;
    let cert_chain = rustls_pemfile::certs(&mut tls_cert.cert_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ArchiveClientError::TlsInit(format!("parse cert pem: {}", e)))?;
    let key_der = rustls_pemfile::private_key(&mut tls_cert.key_pem.as_bytes())
        .map_err(|e| ArchiveClientError::TlsInit(format!("parse key pem: {}", e)))?
        .ok_or_else(|| ArchiveClientError::TlsInit("no private key in pem".into()))?;

    // SAFETY: we install a process-global crypto provider once. Errors here
    // mean another provider was already installed; that's fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert::default()))
        .with_client_auth_cert(
            cert_chain.into_iter().map(CertificateDer::from).collect(),
            key_der_to_owned(key_der),
        )
        .map_err(|e| ArchiveClientError::TlsInit(format!("client_auth_cert: {}", e)))?;

    // ALPN h2 is required for HTTP/2 / gRPC. Without this rustls will
    // negotiate the default protocol and tonic's HTTP/2 client will fail
    // with an opaque transport error.
    config.alpn_protocols = vec![b"h2".to_vec()];

    Ok(Arc::new(config))
}

/// The host of `uri` as a dial target: `Uri` keeps an IPv6 literal in its
/// brackets, which name no host to `TcpStream::connect`.
fn dial_host(uri: &Uri) -> Option<&str> {
    uri.host()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
}

/// Tower service that, given a `Uri`, opens a TCP connection and wraps it
/// in a rustls TLS session using the provided client config. Returns the
/// resulting stream wrapped in `TokioIo` so it satisfies tonic 0.12's
/// `HyperConnection` requirement.
#[derive(Clone)]
pub struct QuilTlsConnector {
    config: Arc<ClientConfig>,
}

impl QuilTlsConnector {
    pub fn new(config: Arc<ClientConfig>) -> Self {
        Self { config }
    }
}

impl Service<Uri> for QuilTlsConnector {
    type Response = TokioIo<tokio_rustls::client::TlsStream<TcpStream>>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let config = self.config.clone();
        Box::pin(async move {
            let host = dial_host(&uri).ok_or_else(|| "missing host in uri".to_string())?;
            let port = uri.port_u16().unwrap_or(443);
            let tcp = TcpStream::connect((host, port)).await?;
            let _ = tcp.set_nodelay(true);
            let connector = TlsConnector::from(config);
            // Quilibrium servers don't validate SNI; "localhost" matches what
            // the Go side uses too.
            let dns_name = ServerName::try_from("localhost".to_string())
                .map_err(|e| format!("invalid sni: {}", e))?;
            let tls = connector.connect(dns_name, tcp).await?;
            Ok(TokioIo::new(tls))
        })
    }
}

/// Custom tonic connector that runs the sntrup761 **PQNoise** handshake — the
/// post-quantum replacement for the Ed448-mTLS path — and hands tonic the
/// secured tokio stream. Same handshake + identity binding as the libp2p
/// transport (`quil_rpc::pqnoise_channel`), so no rustls/cert material is
/// involved; the server's Ed448 identity is authenticated by its signature
/// over the channel-binding handshake hash.
#[derive(Clone)]
pub struct QuilPqNoiseConnector {
    /// The node's 1281-byte Falcon q-prover-key signing key — the `:8340`
    /// network identity presented in the PQNoise handshake.
    falcon_signing_key: Arc<Vec<u8>>,
    expected_peer: Option<quil_p2p::PeerId>,
    refused_peer: Option<quil_p2p::PeerId>,
}

impl QuilPqNoiseConnector {
    pub fn new(falcon_signing_key: Vec<u8>) -> Self {
        Self {
            falcon_signing_key: Arc::new(falcon_signing_key),
            expected_peer: None,
            refused_peer: None,
        }
    }

    pub fn with_expected_peer(mut self, peer: quil_p2p::PeerId) -> Self {
        self.expected_peer = Some(peer);
        self
    }

    /// A connector to this node's own master, which holds the same Falcon
    /// identity: a node answering at the master's address as another is
    /// refused.
    pub fn to_own_master(falcon_signing_key: Vec<u8>) -> Result<Self, Box<ArchiveClientError>> {
        let peer = quil_p2p::Keypair::falcon_from_bytes(&falcon_signing_key)
            .map_err(|error| {
                Box::new(ArchiveClientError::TlsInit(format!(
                    "master identity: {error}"
                )))
            })?
            .public()
            .to_peer_id();
        Ok(Self::new(falcon_signing_key).with_expected_peer(peer))
    }

    /// Fail with [`OwnEndpoint`] when the server is `peer`.
    pub fn refusing_peer(mut self, peer: quil_p2p::PeerId) -> Self {
        self.refused_peer = Some(peer);
        self
    }

    /// Expect the identity pinned for `addr` ([`pin_archive_peer`]) unless
    /// this connector already expects one.
    fn pinned_for(self, addr: &str) -> Self {
        match (self.expected_peer, pinned_archive_peer(addr)) {
            (None, Some(peer)) => self.with_expected_peer(peer),
            _ => self,
        }
    }
}

impl Service<Uri> for QuilPqNoiseConnector {
    type Response = TokioIo<crate::pqnoise_channel::PqTokioStream>;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let falcon_signing_key = self.falcon_signing_key.clone();
        let expected_peer = self.expected_peer;
        let refused_peer = self.refused_peer;
        Box::pin(async move {
            let host = dial_host(&uri).ok_or_else(|| "missing host in uri".to_string())?;
            let port = uri.port_u16().unwrap_or(443);
            let tcp = TcpStream::connect((host, port)).await?;
            let (peer, stream) =
                crate::pqnoise_channel::pq_client_handshake(tcp, falcon_signing_key.as_ref())
                    .await?;
            if expected_peer.is_some_and(|expected| peer != expected) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "PQNoise server identity does not match the expected peer",
                )
                .into());
            }
            if refused_peer == Some(peer) {
                return Err(Box::new(OwnEndpoint) as Box<dyn std::error::Error + Send + Sync>);
            }
            Ok(TokioIo::new(stream))
        })
    }
}

fn key_der_to_owned(key: PrivateKeyDer<'_>) -> PrivateKeyDer<'static> {
    match key {
        PrivateKeyDer::Pkcs1(d) => PrivateKeyDer::Pkcs1(d.secret_pkcs1_der().to_vec().into()),
        PrivateKeyDer::Sec1(d) => PrivateKeyDer::Sec1(d.secret_sec1_der().to_vec().into()),
        PrivateKeyDer::Pkcs8(d) => PrivateKeyDer::Pkcs8(d.secret_pkcs8_der().to_vec().into()),
        _ => panic!("unsupported key type"),
    }
}

// =====================================================================
// Proof-of-possession regression test — CLIENT direction, END-TO-END HANDSHAKE.
//
// Mirror of `quil_tls::tests::acceptor_completes_handshake_with_forged_client_signature`
// for the outbound side. `AcceptAnyServerCert::verify_xsign` proves the
// server's cert is genuine (the Ed448 identity authorized its Ed25519 cert
// key) but NOT that the live server holds the cert's private key. That second
// guarantee is the TLS `CertificateVerify` check, which rustls routes through
// `verify_tls1x_signature`. `AcceptAnyServerCert` now performs that check (it
// previously stubbed those callbacks to `Ok(assertion())`, which let a server
// present a public cert it did not own — signing CertificateVerify with a
// different key — and still be accepted).
//
// The repro drives a real TLS 1.3 handshake through the actual production
// client construction (`build_quil_client_config`) and asserts the client
// REJECTS the forged server. It failed before possession was enforced (the
// handshake succeeded, demonstrating the bypass); it now guards against that
// regression.
// =====================================================================
#[cfg(test)]
mod error_chain_tests {
    #[derive(Debug, thiserror::Error)]
    #[error("{0}")]
    struct Layer(&'static str, #[source] Option<Box<Layer>>);

    #[test]
    fn the_chain_names_every_distinct_cause_below_the_error() {
        let error = Layer(
            "rpc error: h2 protocol error: http2 error",
            Some(Box::new(Layer(
                "http2 error",
                Some(Box::new(Layer("keep-alive timed out", None))),
            ))),
        );
        assert_eq!(super::error_chain(&error), "keep-alive timed out");
        assert_eq!(super::error_chain(&Layer("alone", None)), "");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::sign::CertifiedKey;
    use rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;

    /// A fresh Falcon-512 signing key — the node identity
    /// `build_quil_tls_cert` binds the cert to.
    fn falcon_signing_key() -> Vec<u8> {
        use quil_types::crypto::Signer as _;
        quil_crypto::FalconSigner::generate().private_key().to_vec()
    }

    fn cert_chain_from_key(falcon_sk: &[u8]) -> Vec<CertificateDer<'static>> {
        let tls = build_quil_tls_cert(falcon_sk).unwrap();
        rustls_pemfile::certs(&mut tls.cert_pem.as_bytes())
            .map(|r| r.unwrap())
            .collect()
    }

    /// Load the Ed25519 signing key derived from `falcon_sk`. Pairing this
    /// with a *different* key's cert chain via `CertifiedKey::new` (which —
    /// unlike `from_der` — does not check the key matches the cert) is the
    /// forgery: present someone else's cert, sign with your own key.
    fn signing_key_from_key(falcon_sk: &[u8]) -> Arc<dyn rustls::sign::SigningKey> {
        let tls = build_quil_tls_cert(falcon_sk).unwrap();
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut tls.key_pem.as_bytes())
            .unwrap()
            .unwrap();
        rustls::crypto::ring::sign::any_supported_type(&key).unwrap()
    }

    /// Server resolver presenting a fixed `CertifiedKey` — used to pair a
    /// victim's cert chain with an attacker's (mismatched) key for the forged
    /// repro, and a matched pair for the positive control.
    #[derive(Debug)]
    struct StaticServerCert(Arc<CertifiedKey>);
    impl rustls::server::ResolvesServerCert for StaticServerCert {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<CertifiedKey>> {
            Some(self.0.clone())
        }
    }

    fn acceptor_for(cert: Arc<CertifiedKey>) -> TlsAcceptor {
        // SAFETY: install the default provider once; an error just means
        // another provider is already installed.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(StaticServerCert(cert)));
        // Match the client's ALPN so the handshake fails (or succeeds) on the
        // cert check, not on protocol negotiation.
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        TlsAcceptor::from(Arc::new(cfg))
    }

    #[tokio::test]
    async fn client_rejects_forged_server_signature() {
        // Attacker server: victim's public cert + attacker's own, different
        // key — a server that does NOT possess the cert key.
        let forged = Arc::new(CertifiedKey::new(
            cert_chain_from_key(&falcon_signing_key()),
            signing_key_from_key(&falcon_signing_key()),
        ));
        let acceptor = acceptor_for(forged);

        // Production client, built exactly as the node does.
        let connector =
            TlsConnector::from(build_quil_client_config(&falcon_signing_key()).unwrap());

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_name = ServerName::try_from("localhost").unwrap();
        let (_server_res, client_res) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect(server_name, client_io),
        );

        assert!(
            client_res.is_err(),
            "VULNERABILITY: build_quil_client_config (AcceptAnyServerCert) completed the \
             handshake with a server that presented the victim's cert but signed \
             CertificateVerify with a different key — proof-of-possession is not \
             enforced, so the server identity is spoofable by cert replay",
        );
    }

    /// Positive control: the SAME client must SUCCEED against a legitimate
    /// server that actually possesses its cert's key. Proves the forged test
    /// fails specifically because possession is missing — not because of ALPN,
    /// the duplex transport, or some other setup detail. Passes before and
    /// after the fix (all possession is legitimate).
    #[tokio::test]
    async fn client_accepts_legitimate_server() {
        let sk = falcon_signing_key();
        let legit = Arc::new(CertifiedKey::new(
            cert_chain_from_key(&sk),
            signing_key_from_key(&sk),
        ));
        let acceptor = acceptor_for(legit);

        let connector =
            TlsConnector::from(build_quil_client_config(&falcon_signing_key()).unwrap());

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_name = ServerName::try_from("localhost").unwrap();
        let (server_res, client_res) = tokio::join!(
            acceptor.accept(server_io),
            connector.connect(server_name, client_io),
        );

        assert!(
            client_res.is_ok(),
            "legitimate handshake must succeed (client side): {:?}",
            client_res.err(),
        );
        assert!(
            server_res.is_ok(),
            "legitimate handshake must succeed (server side): {:?}",
            server_res.err(),
        );
    }

    /// Each archive address has its own outage: failures log once when
    /// they begin, and a success ends only that address's outage.
    #[test]
    fn connection_failures_are_one_outage_per_archive() {
        use quil_engine::outage::OutageEvent;
        let (a, b) = ("192.0.2.1:8340", "192.0.2.2:8340");
        assert_eq!(
            super::connect_outage(a, true),
            None,
            "a success without failures logs nothing"
        );
        assert_eq!(super::connect_outage(a, false), Some(OutageEvent::Began));
        assert_eq!(super::connect_outage(a, false), None, "repeats are bounded");
        assert_eq!(
            super::connect_outage(b, false),
            Some(OutageEvent::Began),
            "another archive is separate"
        );
        assert!(matches!(
            super::connect_outage(a, true),
            Some(OutageEvent::Ended { failures: 2, .. })
        ));
        assert_eq!(super::connect_outage(a, true), None);
        assert_eq!(
            super::connect_outage(a, false),
            Some(OutageEvent::Began),
            "a new failure begins anew"
        );
        assert!(matches!(
            super::connect_outage(b, true),
            Some(OutageEvent::Ended { failures: 1, .. })
        ));
    }
}

#[cfg(test)]
mod pinned_archive_tests {
    use super::*;

    #[test]
    fn dial_host_strips_only_the_brackets_of_an_ipv6_literal() {
        for (uri, host) in [
            ("http://[::1]:8340", "::1"),
            ("http://[2001:db8::7]:8340", "2001:db8::7"),
            ("http://203.0.113.7:8340", "203.0.113.7"),
            ("http://node.example.com:8340", "node.example.com"),
        ] {
            assert_eq!(dial_host(&uri.parse().unwrap()), Some(host), "{uri}");
        }
    }

    /// Every stream dial (archives, peers, `qclient --addr [::1]:8340`) goes
    /// through this connector with a bracketed literal.
    #[tokio::test]
    async fn pqnoise_connector_dials_an_ipv6_literal() {
        let listener = match tokio::net::TcpListener::bind("[::1]:0").await {
            Ok(listener) => listener,
            Err(e) => {
                eprintln!("SKIP pqnoise_connector_dials_an_ipv6_literal: no IPv6 loopback: {e}");
                return;
            }
        };
        let address = listener.local_addr().unwrap();
        let server_key = quil_p2p::generate_falcon_signing_key();
        let handshake = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = crate::pqnoise_channel::pq_server_handshake(tcp, &server_key).await;
        });
        let mut connector = QuilPqNoiseConnector::new(quil_p2p::generate_falcon_signing_key());
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            connector.call(format!("http://{address}").parse().unwrap()),
        )
        .await
        .unwrap();
        assert!(result.is_ok(), "{:?}", result.err());
        let _ = handshake.await;
    }

    /// A dial to an endpoint pinned to an archive's identity reaches only
    /// that identity; an endpoint without a pin, and a connector that
    /// already expects a peer, are unchanged.
    #[tokio::test]
    async fn a_pinned_archive_endpoint_must_answer_as_its_archive() {
        for pinned_to_server in [true, false] {
            let peer_of = |key: &[u8]| {
                quil_p2p::Keypair::falcon_from_bytes(key)
                    .unwrap()
                    .public()
                    .to_peer_id()
            };
            let server_key = quil_p2p::generate_falcon_signing_key();
            let server = peer_of(&server_key);
            let other = peer_of(&quil_p2p::generate_falcon_signing_key());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let handshake = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let _ = crate::pqnoise_channel::pq_server_handshake(tcp, &server_key).await;
            });
            let endpoint = address.to_string();
            pin_archive_peer(&endpoint, if pinned_to_server { server } else { other }).unwrap();
            let mut connector = QuilPqNoiseConnector::new(quil_p2p::generate_falcon_signing_key())
                .pinned_for(&endpoint);
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                connector.call(format!("http://{address}").parse().unwrap()),
            )
            .await
            .unwrap();
            assert_eq!(result.is_ok(), pinned_to_server);
            if let Err(error) = result {
                assert!(
                    error.to_string().contains("identity does not match"),
                    "{error}"
                );
            }
            let _ = handshake.await;
            // A later test in this process may listen on the same port.
            ARCHIVE_PEERS.write().unwrap().remove(&endpoint);
        }
        let key = quil_p2p::generate_falcon_signing_key();
        assert_eq!(
            QuilPqNoiseConnector::new(key.clone())
                .pinned_for("192.0.2.1:8340")
                .expected_peer,
            None
        );
        let explicit = quil_p2p::Keypair::falcon_from_bytes(&key)
            .unwrap()
            .public()
            .to_peer_id();
        let pinned = quil_p2p::Keypair::falcon_from_bytes(&quil_p2p::generate_falcon_signing_key())
            .unwrap()
            .public()
            .to_peer_id();
        pin_archive_peer("192.0.2.2:8340", pinned).unwrap();
        assert_eq!(pinned_archive_peer("192.0.2.2:8340"), Some(pinned));
        assert_eq!(
            QuilPqNoiseConnector::new(key)
                .with_expected_peer(explicit)
                .pinned_for("192.0.2.2:8340")
                .expected_peer,
            Some(explicit)
        );
    }

    /// R112-D-2: a pin stays with the peer it names. Pinning the same
    /// endpoint to another peer (one archive's record naming another
    /// archive's address) leaves the first pin, so that archive stays
    /// reachable.
    #[test]
    fn r112_d2_an_archive_pin_is_not_replaced_by_another_peer() {
        let peer = || {
            quil_p2p::Keypair::falcon_from_bytes(&quil_p2p::generate_falcon_signing_key())
                .unwrap()
                .public()
                .to_peer_id()
        };
        let (first, second) = (peer(), peer());
        let endpoint = "198.51.100.1:8340";
        let _ = pin_archive_peer(endpoint, first);
        let _ = pin_archive_peer(endpoint, first);
        let _ = pin_archive_peer(endpoint, second);
        assert_eq!(
            pinned_archive_peer(endpoint),
            Some(first),
            "R112-D-2: a later pin to another peer replaced the archive's pin"
        );
    }
}

#[cfg(test)]
mod pinned_master_tests {
    use super::*;

    /// A worker's connector to its master expects the node's own identity: a
    /// node at the master's address holding another key is refused.
    #[tokio::test]
    async fn a_connector_to_the_own_master_refuses_another_identity() {
        for same_key in [true, false] {
            let client_key = quil_p2p::generate_falcon_signing_key();
            let server_key = if same_key {
                client_key.clone()
            } else {
                quil_p2p::generate_falcon_signing_key()
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                crate::pqnoise_channel::pq_server_handshake(tcp, &server_key)
                    .await
                    .unwrap()
            });
            let mut connector = QuilPqNoiseConnector::to_own_master(client_key).unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                connector.call(format!("http://{address}").parse().unwrap()),
            )
            .await
            .unwrap();
            assert_eq!(result.is_ok(), same_key, "same key: {same_key}");
            if let Err(error) = result {
                assert!(
                    error.to_string().contains("identity does not match"),
                    "{error}"
                );
            }
            let _ = server.await;
        }
    }

    #[tokio::test]
    async fn master_pin_accepts_own_key_and_rejects_a_legitimate_unrelated_peer() {
        for same_key in [true, false] {
            let client_key = quil_p2p::generate_falcon_signing_key();
            let server_key = if same_key {
                client_key.clone()
            } else {
                quil_p2p::generate_falcon_signing_key()
            };
            let expected = quil_p2p::Keypair::falcon_from_bytes(&client_key)
                .unwrap()
                .public()
                .to_peer_id();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                crate::pqnoise_channel::pq_server_handshake(tcp, &server_key)
                    .await
                    .unwrap()
            });
            let mut connector = QuilPqNoiseConnector::new(client_key).with_expected_peer(expected);
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                connector.call(format!("http://{address}").parse().unwrap()),
            )
            .await
            .unwrap();
            assert_eq!(result.is_ok(), same_key);
            if let Err(error) = result {
                assert!(
                    error.to_string().contains("identity does not match"),
                    "{error}"
                );
            }
            assert_eq!(server.await.unwrap().peer_id(), expected);
        }
    }

    #[tokio::test]
    async fn an_archive_answering_with_this_nodes_identity_is_recognized() {
        for own in [true, false] {
            let key = quil_p2p::generate_falcon_signing_key();
            let server_key = if own {
                key.clone()
            } else {
                quil_p2p::generate_falcon_signing_key()
            };
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (tcp, _) = listener.accept().await.unwrap();
                let stream = crate::pqnoise_channel::pq_server_handshake(tcp, &server_key).await;
                tokio::time::sleep(Duration::from_secs(3)).await;
                drop(stream);
            });
            let result = tokio::time::timeout(
                Duration::from_secs(2),
                ArchiveClient::connect_archive(&address.to_string(), &key),
            )
            .await;
            let recognized = matches!(&result, Ok(Err(error)) if error.is_own_endpoint());
            assert_eq!(recognized, own, "own={own}");
            server.abort();
        }
    }

    /// A submission's deadline grows with its size from the 15 s every
    /// other request keeps, and stays under the archives' 120 s.
    #[test]
    fn a_submission_deadline_grows_with_its_size_under_the_archives_limit() {
        assert_eq!(submit_deadline(0), REQUEST_TIMEOUT);
        assert_eq!(submit_deadline(32 * 1024 - 1), REQUEST_TIMEOUT);
        assert_eq!(submit_deadline(32 * 1024), Duration::from_secs(16));
        assert_eq!(submit_deadline(541_968), Duration::from_secs(31));
        assert_eq!(submit_deadline(1_460_000), Duration::from_secs(59));
        assert_eq!(submit_deadline(4 << 20), SUBMIT_DEADLINE_CAP);
        assert_eq!(submit_deadline(usize::MAX), SUBMIT_DEADLINE_CAP);
        assert!(SUBMIT_DEADLINE_CAP < Duration::from_secs(120));
    }

    #[test]
    fn a_closed_connection_is_a_transport_failure_and_a_status_is_not() {
        let closed = tonic::Status::from_error(Box::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection closed",
        )));
        assert!(ArchiveClientError::Rpc(closed).is_transport_failure());
        assert!(
            !ArchiveClientError::Rpc(tonic::Status::not_found("frame 7 not found"))
                .is_transport_failure()
        );
    }
}

#[cfg(test)]
mod off_thread_dial_tests {
    use super::*;
    use quil_types::proto::global::app_shard_service_server::AppShardServiceServer;
    use quil_types::proto::global::FrameHeader;
    use std::time::Instant;

    /// An archive's deadline for a client's PQNoise handshake, scaled down
    /// from its 10 s.
    const DEADLINE: Duration = Duration::from_secs(3);

    /// Serves frames whose header output has a fixed size.
    struct Frames(usize);

    #[tonic::async_trait]
    impl crate::stub_services::AppShardFrameProvider for Frames {
        async fn get_app_shard_frame(
            &self,
            _filter: Vec<u8>,
            frame_number: u64,
        ) -> Result<Option<AppShardFrame>, tonic::Status> {
            let header = FrameHeader {
                frame_number,
                output: vec![0x5a; self.0],
                ..Default::default()
            };
            Ok(Some(AppShardFrame {
                header: Some(header),
                ..Default::default()
            }))
        }
    }

    /// An archive's peer listener: a PQNoise handshake within `deadline`,
    /// then `AppShardService` over the stream, with h2 keepalive pings at
    /// `keepalive` (interval, timeout) when given.
    struct Archive {
        runtime: Option<tokio::runtime::Runtime>,
        address: String,
        /// Each handshake's outcome: completed, failed or timed out.
        handshakes: std::sync::mpsc::Receiver<&'static str>,
    }

    impl Archive {
        fn serve(
            threads: usize,
            deadline: Duration,
            keepalive: Option<(Duration, Duration)>,
            frame_bytes: usize,
        ) -> Self {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(threads)
                .enable_all()
                .build()
                .unwrap();
            let server_key = quil_p2p::generate_falcon_signing_key();
            let listener = runtime
                .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
                .unwrap();
            let address = listener.local_addr().unwrap().to_string();
            let (handshakes_tx, handshakes) = std::sync::mpsc::channel();
            let (streams_tx, streams) = tokio::sync::mpsc::unbounded_channel();
            runtime.spawn(async move {
                loop {
                    let (tcp, _) = listener.accept().await.unwrap();
                    let (key, handshakes_tx, streams_tx) = (
                        server_key.clone(),
                        handshakes_tx.clone(),
                        streams_tx.clone(),
                    );
                    tokio::spawn(async move {
                        // As an archive does: a handshake past the deadline is dropped.
                        let outcome = tokio::time::timeout(
                            deadline,
                            crate::pqnoise_channel::pq_server_handshake(tcp, &key),
                        )
                        .await;
                        let _ = handshakes_tx.send(match outcome {
                            Ok(Ok(stream)) => {
                                let _ = streams_tx.send(Ok::<_, std::io::Error>(stream));
                                "completed"
                            }
                            Ok(Err(_)) => "failed",
                            Err(_) => "timed out",
                        });
                    });
                }
            });
            let frames = crate::stub_services::AppShardRpcServer::with_provider(Arc::new(Frames(
                frame_bytes,
            )));
            runtime.spawn(
                tonic::transport::Server::builder()
                    .http2_keepalive_interval(keepalive.map(|(interval, _)| interval))
                    .http2_keepalive_timeout(keepalive.map(|(_, timeout)| timeout))
                    .add_service(AppShardServiceServer::new(frames))
                    .serve_with_incoming(tokio_stream::wrappers::UnboundedReceiverStream::new(
                        streams,
                    )),
            );
            Archive {
                runtime: Some(runtime),
                address,
                handshakes,
            }
        }
    }

    impl Drop for Archive {
        fn drop(&mut self) {
            if let Some(runtime) = self.runtime.take() {
                runtime.shutdown_background();
            }
        }
    }

    fn current_thread() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// A dial from a current-thread runtime completes, and its channel
    /// answers, although that runtime's only thread is blocked past the
    /// archive's handshake deadline: an in-process worker whose thread a
    /// synchronous call stalls keeps its archive connections.
    #[test]
    fn a_dial_completes_while_its_calling_thread_is_blocked_past_the_handshake_deadline() {
        let archive = Archive::serve(2, DEADLINE, None, 16);
        let worker = current_thread();
        let client_key = quil_p2p::generate_falcon_signing_key();
        let address = archive.address.clone();
        let dialed = worker.block_on(async move {
            let dial =
                tokio::spawn(
                    async move { ArchiveClient::connect_mtls(&address, &client_key).await },
                );
            // The dial takes its first step before this task resumes...
            tokio::task::yield_now().await;
            // ...then a synchronous call blocks this runtime's only thread
            // for twice the archive's deadline.
            std::thread::sleep(DEADLINE * 2);
            dial.await.unwrap()
        });
        assert_eq!(
            archive.handshakes.recv_timeout(Duration::from_secs(5)),
            Ok("completed")
        );
        let mut client = dialed.expect("the dial completes");
        let answered = worker.block_on(client.get_app_shard_frame(vec![0x21; 32], 1));
        assert_eq!(
            answered
                .expect("the channel answers")
                .and_then(|frame| frame.header)
                .map(|h| h.frame_number),
            Some(1)
        );
    }

    /// An established channel answers the archive's keepalive pings while
    /// the thread that dialed it is blocked for longer than the archive
    /// waits for an answer (scaled down from its 20 s interval and 10 s
    /// timeout): the archive keeps the connection, and the next call needs
    /// no new handshake.
    #[test]
    fn an_established_channel_survives_its_calling_thread_blocked_past_the_archive_keepalive() {
        let (interval, timeout) = (Duration::from_millis(500), Duration::from_secs(1));
        let archive = Archive::serve(2, DEADLINE, Some((interval, timeout)), 16);
        let worker = current_thread();
        let client_key = quil_p2p::generate_falcon_signing_key();
        let mut client = worker
            .block_on(ArchiveClient::connect_mtls(&archive.address, &client_key))
            .expect("the dial completes");
        assert!(worker
            .block_on(client.get_app_shard_frame(vec![0x21; 32], 1))
            .is_ok());
        assert_eq!(
            archive.handshakes.try_iter().collect::<Vec<_>>(),
            vec!["completed"]
        );
        // A synchronous call blocks the worker thread for twice as long as
        // an unanswered ping keeps the connection.
        worker.block_on(async { std::thread::sleep((interval + timeout) * 2) });
        let answered = worker.block_on(client.get_app_shard_frame(vec![0x21; 32], 2));
        assert_eq!(
            answered
                .expect("the channel answers")
                .and_then(|frame| frame.header)
                .map(|h| h.frame_number),
            Some(2)
        );
        assert_eq!(
            archive.handshakes.try_iter().collect::<Vec<_>>(),
            Vec::<&str>::new(),
            "the channel reconnected"
        );
    }

    fn env_or(name: &str, default: usize) -> usize {
        std::env::var(name)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    }

    fn secs(duration: Duration) -> String {
        format!("{:.2}", duration.as_secs_f64())
    }

    /// Download throughput of many channels, each dialed from its own
    /// current-thread runtime as in-process workers do, through the PQNoise
    /// stack: dialed on [`archive_io`], whose two threads then carry every
    /// channel's I/O, and dialed on each caller's runtime. Prints, per mode,
    /// the aggregate MiB/s and the per-channel dial and download times.
    ///
    /// `ARCHIVE_IO_BENCH_CHANNELS` (48) channels each download
    /// `ARCHIVE_IO_BENCH_MIB` (4) frames of 1 MiB; the archive runs
    /// `ARCHIVE_IO_BENCH_SERVER_THREADS` (8) threads and drops handshakes
    /// after its 10 s deadline. In the project image:
    /// `cargo test --release --locked -p quil-rpc --lib archive_io_throughput -- --ignored --nocapture`
    #[test]
    #[ignore = "a throughput measurement, run by hand"]
    fn archive_io_throughput() {
        let channels = env_or("ARCHIVE_IO_BENCH_CHANNELS", 48);
        let frames = env_or("ARCHIVE_IO_BENCH_MIB", 4) as u64;
        // The archive's own handshake deadline.
        let deadline = Duration::from_secs(10);
        let archive = Archive::serve(
            env_or("ARCHIVE_IO_BENCH_SERVER_THREADS", 8),
            deadline,
            None,
            1 << 20,
        );
        let client_key = quil_p2p::generate_falcon_signing_key();
        let host_threads = std::thread::available_parallelism().map_or(0, |n| n.get());
        println!("archive I/O throughput: {channels} channels x {frames} MiB, {host_threads} host threads");
        for (mode, off_thread) in [
            ("dialed on archive-io", true),
            ("dialed on each caller's runtime", false),
        ] {
            let ready = Arc::new(std::sync::Barrier::new(channels + 1));
            let workers: Vec<_> = (0..channels)
                .map(|_| {
                    let (address, key, ready) =
                        (archive.address.clone(), client_key.clone(), ready.clone());
                    std::thread::spawn(move || {
                        let worker = current_thread();
                        let started = Instant::now();
                        let dialed = worker.block_on(ArchiveClient::dial_pq(
                            &address,
                            QuilPqNoiseConnector::new(key),
                            off_thread,
                            REQUEST_TIMEOUT,
                            Location::caller(),
                        ));
                        let dial = started.elapsed();
                        ready.wait();
                        let mut client = match dialed {
                            Ok(client) => client,
                            Err(error) => return (dial, Err(format!("dial: {error}"))),
                        };
                        let started = Instant::now();
                        let downloaded = worker.block_on(async {
                            let mut bytes = 0;
                            for frame_number in 1..=frames {
                                let frame = client
                                    .get_app_shard_frame(vec![0x21; 32], frame_number)
                                    .await;
                                bytes += frame
                                    .map_err(|error| format!("frame {frame_number}: {error}"))?
                                    .and_then(|frame| frame.header)
                                    .map_or(0, |header| header.output.len());
                            }
                            Ok::<_, String>(bytes)
                        });
                        (dial, downloaded.map(|bytes| (bytes, started.elapsed())))
                    })
                })
                .collect();
            ready.wait();
            let started = Instant::now();
            let results: Vec<_> = workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect();
            let wall = started.elapsed();
            let mut dials: Vec<_> = results.iter().map(|(dial, _)| *dial).collect();
            let mut done: Vec<_> = results
                .iter()
                .filter_map(|(_, outcome)| outcome.as_ref().ok().map(|(_, at)| *at))
                .collect();
            let bytes: usize = results
                .iter()
                .filter_map(|(_, outcome)| outcome.as_ref().ok().map(|(bytes, _)| *bytes))
                .sum();
            let failures: Vec<_> = results
                .iter()
                .filter_map(|(_, outcome)| outcome.as_ref().err())
                .collect();
            dials.sort();
            done.sort();
            let spread = |times: &[Duration]| match times {
                [] => "none".to_string(),
                _ => format!(
                    "min {} median {} max {} s",
                    secs(times[0]),
                    secs(times[times.len() / 2]),
                    secs(times[times.len() - 1])
                ),
            };
            println!(
                "{mode}: {:.1} MiB/s aggregate, {} MiB in {} s; {} failed{}",
                bytes as f64 / (1 << 20) as f64 / wall.as_secs_f64(),
                bytes >> 20,
                secs(wall),
                failures.len(),
                failures
                    .first()
                    .map_or(String::new(), |error| format!(" (first: {error})"))
            );
            println!("  dial: {}", spread(&dials));
            println!("  download: {}", spread(&done));
            println!(
                "  per-channel download completion (s, sorted): {}",
                done.iter()
                    .map(|at| secs(*at))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
            let handshakes: Vec<_> = archive.handshakes.try_iter().collect();
            let count = |outcome: &str| handshakes.iter().filter(|seen| **seen == outcome).count();
            println!(
                "  archive handshakes: {} completed, {} timed out ({} s deadline), {} failed",
                count("completed"),
                count("timed out"),
                deadline.as_secs(),
                count("failed")
            );
        }
    }
}

#[cfg(test)]
mod flow_control_tests {
    use super::*;
    use crate::global_service::{FrameLookup, GlobalRpcServer};
    use quil_types::proto::global::app_shard_service_server::AppShardServiceServer;
    use quil_types::proto::global::global_service_server::GlobalServiceServer;
    use quil_types::proto::global::{self, FrameHeader};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
    use tokio::net::TcpListener;
    use tokio::time::Instant;

    /// One-way latency of the test link; a round trip is twice this. A
    /// request or response takes one round trip when its receiver grants it
    /// whole, and one more per window it overflows: each test allows two.
    const DELAY: Duration = Duration::from_millis(250);

    struct NoFrames;
    impl FrameLookup for NoFrames {
        fn get_latest_frame(&self) -> Result<global::GlobalFrame, String> {
            Err("n/a".into())
        }
        fn get_frame(&self, _: u64) -> Result<global::GlobalFrame, String> {
            Err("n/a".into())
        }
    }

    /// Serves app frames whose header output has a fixed size.
    struct Frames(usize);

    #[tonic::async_trait]
    impl crate::stub_services::AppShardFrameProvider for Frames {
        async fn get_app_shard_frame(
            &self,
            _filter: Vec<u8>,
            frame_number: u64,
        ) -> Result<Option<AppShardFrame>, tonic::Status> {
            Ok(Some(AppShardFrame {
                header: Some(FrameHeader {
                    frame_number,
                    output: vec![0x5a; self.0],
                    ..Default::default()
                }),
                ..Default::default()
            }))
        }
    }

    /// Writes what `from` reads to `to`, each chunk [`DELAY`] after it was
    /// read, and never holds the reader back: a link with that latency and
    /// no bandwidth limit.
    async fn delayed_copy(mut from: OwnedReadHalf, mut to: OwnedWriteHalf) {
        let (chunks, mut queued) = tokio::sync::mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
        tokio::spawn(async move {
            while let Some((due, chunk)) = queued.recv().await {
                tokio::time::sleep_until(due).await;
                if to.write_all(&chunk).await.is_err() {
                    return;
                }
            }
            let _ = to.shutdown().await;
        });
        let mut buf = vec![0; 64 * 1024];
        while let Ok(n @ 1..) = from.read(&mut buf).await {
            if chunks
                .send((Instant::now() + DELAY, buf[..n].to_vec()))
                .is_err()
            {
                return;
            }
        }
    }

    /// A `:8340` peer listener as the node builds it, reached over a link of
    /// [`DELAY`] each way: the address to dial. It records the size of each
    /// consensus message delivered to it in `delivered`, and serves app
    /// frames with `frame_bytes` of output.
    async fn far_peer(delivered: Arc<std::sync::Mutex<Vec<usize>>>, frame_bytes: usize) -> String {
        let server_key = quil_p2p::generate_falcon_signing_key();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = listener.local_addr().unwrap();
        let (streams_tx, streams) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let (key, streams_tx) = (server_key.clone(), streams_tx.clone());
                tokio::spawn(async move {
                    if let Ok(stream) = crate::pqnoise_channel::pq_server_handshake(tcp, &key).await
                    {
                        let _ = streams_tx.send(Ok::<_, std::io::Error>(stream));
                    }
                });
            }
        });
        let global = GlobalRpcServer::new(Arc::new(NoFrames)).with_consensus_delivery(Arc::new(
            move |request: tonic::Request<global::SubmitGlobalConsensusRequest>| {
                delivered.lock().unwrap().push(request.get_ref().data.len());
                Ok(())
            },
        ));
        let frames =
            crate::stub_services::AppShardRpcServer::with_provider(Arc::new(Frames(frame_bytes)));
        tokio::spawn(
            crate::pqnoise_channel::peer_server()
                .add_service(
                    GlobalServiceServer::new(global).max_decoding_message_size(64 * 1024 * 1024),
                )
                .add_service(
                    AppShardServiceServer::new(frames).max_encoding_message_size(64 * 1024 * 1024),
                )
                .serve_with_incoming(tokio_stream::wrappers::UnboundedReceiverStream::new(
                    streams,
                )),
        );

        let link = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = link.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            while let Ok((near, _)) = link.accept().await {
                let Ok(far) = TcpStream::connect(peer).await else {
                    continue;
                };
                let (near_read, near_write) = near.into_split();
                let (far_read, far_write) = far.into_split();
                tokio::spawn(delayed_copy(near_read, far_write));
                tokio::spawn(delayed_copy(far_read, near_write));
            }
        });
        address
    }

    /// A client on a cached connection to the far peer: the connection's
    /// settings and windows are in place, as on the GLOBAL publisher's.
    async fn connected(address: &str) -> ArchiveClient {
        let client_key = quil_p2p::generate_falcon_signing_key();
        let mut client = ArchiveClient::connect_mtls(address, &client_key)
            .await
            .expect("dials the far peer");
        client
            .submit_global_consensus(vec![3], vec![1; 1024])
            .await
            .expect("delivers a vote");
        client
    }

    /// A multi-MB GLOBAL block reaches a far peer in one round trip, as a
    /// vote does: the peer's listener grants the whole body at once. With
    /// hyper's server default of 1 MiB it took at least three, and the
    /// committee finalized from the votes before the block reached a far
    /// archive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_multi_megabyte_block_reaches_a_far_peer_in_one_round_trip() {
        let block = 3 << 20;
        let delivered = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut client = connected(&far_peer(delivered.clone(), 0).await).await;
        let started = Instant::now();
        client
            .submit_global_consensus(vec![3], vec![2; block])
            .await
            .expect("delivers the block");
        let took = started.elapsed();
        assert_eq!(*delivered.lock().unwrap(), [1024, block]);
        assert!(
            took < DELAY * 4,
            "a {block}-byte block took {took:?} at a {:?} round trip",
            DELAY * 2
        );
    }

    /// A multi-MB frame from a far peer arrives in one round trip: the
    /// client grants the whole response at once. With hyper's client
    /// default of 2 MiB per stream it took at least three.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_multi_megabyte_response_arrives_from_a_far_peer_in_one_round_trip() {
        let output = 6 << 20;
        let delivered = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut client = connected(&far_peer(delivered, output).await).await;
        let started = Instant::now();
        let frame = client
            .get_app_shard_frame(vec![0x21; 32], 1)
            .await
            .expect("answers the frame read");
        let took = started.elapsed();
        assert_eq!(
            frame.and_then(|f| f.header).map(|h| h.output.len()),
            Some(output)
        );
        assert!(
            took < DELAY * 4,
            "a {output}-byte response took {took:?} at a {:?} round trip",
            DELAY * 2
        );
    }
}

#[cfg(test)]
mod endpoint_load_tests {
    use super::*;

    #[track_caller]
    fn here() -> Site {
        Location::caller()
    }

    /// Past 32 connections to one endpoint the node warns once, naming the
    /// call sites that hold them, again only after ten minutes, and logs one
    /// line once the count falls back to half.
    #[test]
    fn many_connections_to_one_endpoint_warn_once_per_interval_and_end_with_one_line() {
        let start = Instant::now();
        let busy = here();
        let other = here();
        let mut load = EndpointLoad {
            open: ENDPOINT_CONNECTIONS_WARN,
            ..Default::default()
        };
        load.sites.insert(busy, ENDPOINT_CONNECTIONS_WARN);
        assert_eq!(load.note(start), None, "at the threshold");
        load.dialing = 2;
        load.sites.insert(other, 2);
        load.dials.extend([start, start]);
        let Some(LoadLine::Many {
            open,
            dialing,
            dials_last_60s,
            sites,
        }) = load.note(start)
        else {
            panic!("no warning past the threshold");
        };
        assert_eq!((open, dialing, dials_last_60s), (32, 2, 2));
        assert_eq!(
            sites,
            format!(
                "{}:{}=32 {}:{}=2",
                busy.file(),
                busy.line(),
                other.file(),
                other.line()
            )
        );
        let later = start + Duration::from_secs(120);
        assert_eq!(load.note(later), None, "warned again within ten minutes");
        let much_later = start + ENDPOINT_LOAD_WARN_EVERY;
        assert!(matches!(
            load.note(much_later),
            Some(LoadLine::Many {
                dials_last_60s: 0,
                ..
            })
        ));
        load.open = 20;
        load.dialing = 0;
        assert_eq!(
            load.note(much_later),
            None,
            "ended above half the threshold"
        );
        load.open = 16;
        assert_eq!(
            load.note(much_later + Duration::from_secs(5)),
            Some(LoadLine::Normal {
                open: 16,
                dialing: 0,
                peak: 34,
                secs: 605
            })
        );
        assert_eq!(load.note(much_later + Duration::from_secs(6)), None);
        assert!(
            !load.forgettable(much_later),
            "a recent warning still paces"
        );
        assert!(!load.forgettable(much_later + ENDPOINT_LOAD_WARN_EVERY));
        load.open = 0;
        assert!(load.forgettable(much_later + ENDPOINT_LOAD_WARN_EVERY));
    }

    /// A PQNoise connection counts as dialing during its dial and as open
    /// until the last clone of its client drops.
    #[tokio::test]
    async fn a_connection_counts_as_open_until_its_last_clone_drops() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server_key = quil_p2p::generate_falcon_signing_key();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let key = server_key.clone();
                tokio::spawn(async move {
                    let stream = crate::pqnoise_channel::pq_server_handshake(tcp, &key).await;
                    std::future::pending::<()>().await;
                    drop(stream);
                });
            }
        });
        let key = quil_p2p::generate_falcon_signing_key();
        assert_eq!(endpoint_load(&address), (0, 0));
        let client = ArchiveClient::connect_mtls(&address, &key).await.unwrap();
        let copy = client.clone();
        assert_eq!(endpoint_load(&address), (1, 0));
        drop(client);
        assert_eq!(endpoint_load(&address), (1, 0), "a clone still holds it");
        drop(copy);
        assert_eq!(
            endpoint_load(&address),
            (0, 0),
            "the connection stayed counted"
        );
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let refused = closed.local_addr().unwrap().to_string();
        drop(closed);
        assert!(ArchiveClient::connect_mtls(&refused, &key).await.is_err());
        assert_eq!(
            endpoint_load(&refused),
            (0, 0),
            "a failed dial stayed counted"
        );
    }
}
