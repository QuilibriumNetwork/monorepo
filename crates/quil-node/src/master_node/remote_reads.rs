//! Forwarding a state read to a node that holds the application.
//!
//! Serve from local workers when this node covers the shards; otherwise ask
//! the nodes that do, and reach for an archive only when none of them answers. A wallet talks to its own node and that node finds the
//! data, rather than the operator hunting for a node with the right coverage.
//!
//! The forwarded read rides the existing peer transport — the Falcon-mTLS
//! `:8340` listener every node already runs — as `AppShardService.ListShardCoins`,
//! so it inherits that channel's authentication instead of introducing a second
//! node-to-node path.
//!
//! What comes back is not trusted on the strength of who said it: a coin page
//! carries the accumulator root record, the wallet checks each coin against it,
//! and a spend's witness must match a root the network retains, so a peer that
//! fabricates coins is refused at admission. The residual risk is a peer that
//! omits — answered by asking a covering node first (it has the data and is
//! accountable for the shard) and by a peer refusing outright for an
//! application it does not serve, rather than returning an empty page.
//!
//! A covering node is a registered prover serving the application's shards:
//! any key can sign a PeerInfo claiming an application, so a claim counts
//! only for the shards its signer holds an allocation on, and the dial must
//! reach that signer.
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quil_rpc::ArchiveClientError;
use quil_types::store::{CoinData, CoinPageData, EscrowPageData};

/// Separate budgets for covering peers and archive fallback. Unreachable or
/// stale covering peers must not consume the archive attempts.
const MAX_ATTEMPTS: usize = 3;
/// Serving nodes build witnesses under a small worker limit and refuse rather
/// than queue. Five wallets spending at once on a live width run found every
/// endpoint busy within two seconds and two transfers failed, though the same
/// nodes served the other three moments later. A refused round is retried
/// within this budget.
/// How long a forwarded read keeps asking the covering nodes. A node whose
/// coin workers are all busy refuses at once, so one pass over the peers can
/// fail within seconds while several wallets prove at the same time.
const READ_RETRY_BUDGET: Duration = Duration::from_secs(60);
const READ_RETRY_DELAY: Duration = Duration::from_secs(3);
/// The most one peer gets to deliver one attempt at a coin page, its body
/// included: the 15 s request deadline ends at the answer's headers. A page
/// is 0.98 MB of 64 coins, so this asks for 24 KB/s; a slower path is cut here
/// and asked for less. Mainnet's first slow path ran at 40 KB/s (34 s a page).
const PAGE_ATTEMPT: Duration = Duration::from_secs(40);
/// The answer to a wallet comes within [`READ_RETRY_BUDGET`] (the last attempt
/// starts by then) plus [`PAGE_ATTEMPT`], under the deadline of a wallet's call
/// to its node (`qclient`'s channel timeout, 120 s).
const _: () = assert!(READ_RETRY_BUDGET.as_secs() + PAGE_ATTEMPT.as_secs() < 120);
/// A coin page's next attempt after its transfer failed asks for this share of
/// the coins, down to the page every node answers, whatever its build.
const PAGE_SHRINK: u32 = 4;
const SMALLEST_PAGE: u32 = quil_types::store::DEFAULT_SCAN_PAGE_ENTRIES as u32;

fn smaller_page(entries: u32) -> u32 {
    (entries / PAGE_SHRINK).max(SMALLEST_PAGE).min(entries)
}

/// Run `attempt` until it yields a value or `budget` would run out before the
/// next try, `delay` apart.
async fn retry_within<T, F, Fut>(budget: Duration, delay: Duration, mut attempt: F) -> Option<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    retry_until_ok(budget, delay, || {
        let pending = attempt();
        async move { pending.await.ok_or(()) }
    })
    .await
    .ok()
}

/// [`retry_within`], keeping the last attempt's error.
async fn retry_until_ok<T, E, F, Fut>(
    budget: Duration,
    delay: Duration,
    mut attempt: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let deadline = Instant::now() + budget;
    loop {
        let error = match attempt().await {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        if Instant::now() + delay > deadline {
            return Err(error);
        }
        tokio::time::sleep(delay).await;
    }
}
const MAX_PINNED_SCANS: usize = 256;
const SCAN_PIN_TTL: Duration = Duration::from_secs(300);
/// Forwarded reads keep their connection to each endpoint this long after
/// its last use. A wallet pages through an application one forwarded call
/// at a time, and a fresh PQNoise dial per page took about 0.8 s of each
/// 0.86 s page on mainnet.
const CONNECTION_IDLE: Duration = Duration::from_secs(60);
/// A kept connection that fails sooner than this was closed while unused, and
/// the call goes again at once. One failing later died under the transfer; a
/// retry of the same size at once would only take as long again.
const STALE_CONNECTION_FAILURE: Duration = Duration::from_secs(2);
/// Endpoints with a kept connection; the least recently used goes first.
const MAX_CONNECTIONS: usize = 16;
/// A forwarded page taking longer than this makes its scan or listing end with
/// a warning. The scan's total says nothing: it grows with the wallet's coins,
/// so a healthy scan of thousands takes minutes.
const SLOW_PAGE: Duration = Duration::from_secs(10);
/// A peer's decline is logged at info at most this often per endpoint.
const DECLINE_LOG_INTERVAL: Duration = Duration::from_secs(60);
/// Distinct decline reasons named in a refusal, and each reason's length.
const MAX_REASONS: usize = 4;
const MAX_REASON_CHARS: usize = 200;

fn bounded_reason(reason: &str) -> String {
    reason.chars().take(MAX_REASON_CHARS).collect()
}

/// Whether the shards' paths cover a whole application
/// ([`super::grpc::shard_paths_cover_application`]).
fn covers<'a, 'b: 'a>(shards: impl Iterator<Item = &'a (&'b [u8], Vec<bool>)>) -> bool {
    let paths: Vec<Vec<bool>> = shards.map(|(_, path)| path.clone()).collect();
    super::grpc::shard_paths_cover_application(&paths)
}

/// An error with its causes: tonic's transport error alone says only
/// "transport error", not that the connection was refused or timed out.
fn with_causes(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        let part = next.to_string();
        if !text.contains(&part) {
            text.push_str(": ");
            text.push_str(&part);
        }
        cause = next.source();
    }
    text
}

/// Why the peers asked for one forwarded read declined, for the wallet's
/// status: each distinct reason with its count, bounded.
#[derive(Default)]
struct Declines(Vec<(String, usize)>);

impl Declines {
    fn push(&mut self, reason: &str) {
        let reason = bounded_reason(reason);
        match self.0.iter_mut().find(|(known, _)| *known == reason) {
            Some((_, count)) => *count += 1,
            None => self.0.push((reason, 1)),
        }
    }

    fn summary(&self) -> String {
        let total: usize = self.0.iter().map(|(_, count)| count).sum();
        if total == 0 {
            return "no covering node or archive is known".into();
        }
        let mut parts: Vec<_> = self
            .0
            .iter()
            .take(MAX_REASONS)
            .map(|(reason, count)| format!("{count}x {reason}"))
            .collect();
        if self.0.len() > MAX_REASONS {
            parts.push(format!("and {} other reasons", self.0.len() - MAX_REASONS));
        }
        format!(
            "{total} {} declined: {}",
            if total == 1 { "peer" } else { "peers" },
            parts.join("; ")
        )
    }
}

/// Opens a connection to an endpoint for forwarded reads, which must answer
/// as the endpoint's peer when it names one.
type Dial<C> = Arc<
    dyn Fn(
            ReadEndpoint,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<C, ArchiveClientError>> + Send>,
        > + Send
        + Sync,
>;

/// Why a peer did not deliver a coin page.
struct Decline {
    reason: String,
    /// The transfer failed or ran out of time, rather than the peer refusing:
    /// a smaller page can get through where this one did not.
    transfer: bool,
}

/// Why nobody delivered a coin page on one attempt.
struct PageRefusal {
    reasons: String,
    transfer: bool,
}

/// A status with its causes: tonic's message for a connection lost under an
/// answer is "h2 protocol error: error reading a body from connection", and
/// what lost it is only in the source chain.
fn status_reason(status: &tonic::Status) -> String {
    let mut text = format!("{:?}: {}", status.code(), status.message());
    let mut cause = std::error::Error::source(status);
    while let Some(next) = cause {
        let part = next.to_string();
        if !text.contains(&part) {
            text.push_str(": ");
            text.push_str(&part);
        }
        cause = next.source();
    }
    text
}

/// Why a call through [`ReadConnections`] failed.
enum CallError {
    /// No connection to the endpoint could be made.
    Dial(ArchiveClientError),
    /// The call failed on a connection.
    Call(ArchiveClientError),
}

/// The connection `error` came over is no longer usable: it failed in the
/// transport (closed, reset, gone away) or the call outran its deadline.
fn connection_failed(error: &ArchiveClientError) -> bool {
    matches!(error, ArchiveClientError::Transport(_))
        || error.is_transport_failure()
        || error.is_timeout()
}

/// One connection per endpoint, shared by every forwarded read: each new one
/// costs a PQNoise handshake. A connection is dropped when a call on it fails
/// in the transport or times out, once unused for `idle` (a sweep runs while
/// any is kept), and least recently used first beyond `capacity` endpoints.
/// The lock guards only the map, never a dial or a call; clones of a client
/// share its connection. A connection is kept per [`ReadEndpoint`], the
/// address and the peer that must answer there: one dialed as a covering
/// prover never serves a read meant for another peer or for an archive at
/// that address, and an archive's keeps the identity pinned for it at its
/// dial, as a fresh dial per call did.
struct ReadConnections<C> {
    dial: Dial<C>,
    idle: Duration,
    capacity: usize,
    stale_failure: Duration,
    open: Arc<parking_lot::Mutex<OpenConnections<C>>>,
}

struct OpenConnections<C> {
    by_endpoint: HashMap<ReadEndpoint, KeptConnection<C>>,
    next_id: u64,
    sweeping: bool,
}

struct KeptConnection<C> {
    client: C,
    id: u64,
    used: Instant,
}

impl<C> OpenConnections<C> {
    fn expire(&mut self, idle: Duration) {
        self.by_endpoint
            .retain(|_, kept| kept.used.elapsed() < idle);
    }
}

impl<C: Clone + Send + 'static> ReadConnections<C> {
    fn new(dial: Dial<C>, idle: Duration, capacity: usize) -> Self {
        Self {
            dial,
            idle,
            capacity,
            stale_failure: STALE_CONNECTION_FAILURE,
            open: Arc::new(parking_lot::Mutex::new(OpenConnections {
                by_endpoint: HashMap::new(),
                next_id: 0,
                sweeping: false,
            })),
        }
    }

    /// A connection to `endpoint`, its id and whether it was kept from an
    /// earlier call. A new one counts in `dials`.
    async fn connect(
        &self,
        endpoint: &ReadEndpoint,
        dials: &AtomicU64,
    ) -> Result<(C, u64, bool), ArchiveClientError> {
        {
            let mut open = self.open.lock();
            open.expire(self.idle);
            if let Some(kept) = open.by_endpoint.get_mut(endpoint) {
                kept.used = Instant::now();
                return Ok((kept.client.clone(), kept.id, true));
            }
        }
        dials.fetch_add(1, Ordering::Relaxed);
        let client = (self.dial)(endpoint.clone()).await?;
        let mut open = self.open.lock();
        open.next_id += 1;
        let id = open.next_id;
        if open.by_endpoint.len() >= self.capacity && !open.by_endpoint.contains_key(endpoint) {
            if let Some(oldest) = open
                .by_endpoint
                .iter()
                .min_by_key(|(_, kept)| kept.used)
                .map(|(endpoint, _)| endpoint.clone())
            {
                open.by_endpoint.remove(&oldest);
            }
        }
        open.by_endpoint.insert(
            endpoint.clone(),
            KeptConnection {
                client: client.clone(),
                id,
                used: Instant::now(),
            },
        );
        self.sweep_while_kept(&mut open);
        Ok((client, id, false))
    }

    /// Drop connection `id` to `endpoint`, unless another replaced it.
    fn discard(&self, endpoint: &ReadEndpoint, id: u64) {
        let mut open = self.open.lock();
        if open
            .by_endpoint
            .get(endpoint)
            .is_some_and(|kept| kept.id == id)
        {
            open.by_endpoint.remove(endpoint);
        }
    }

    /// Expire idle connections every half `idle` while any is kept, so an
    /// unused one closes within one and a half times `idle`.
    fn sweep_while_kept(&self, open: &mut OpenConnections<C>) {
        if open.sweeping {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        open.sweeping = true;
        let (shared, idle) = (Arc::downgrade(&self.open), self.idle);
        runtime.spawn(async move {
            loop {
                tokio::time::sleep(idle / 2).await;
                let Some(shared) = shared.upgrade() else {
                    return;
                };
                let mut open = shared.lock();
                open.expire(idle);
                if open.by_endpoint.is_empty() {
                    open.sweeping = false;
                    return;
                }
            }
        });
    }

    /// `call` on a connection to `endpoint`. A kept connection that soon fails
    /// in the transport (the peer closed it while unused) is replaced and the
    /// call made once more at once; any connection that failed is dropped.
    async fn call<T, F, Fut>(
        &self,
        endpoint: &ReadEndpoint,
        dials: &AtomicU64,
        mut call: F,
    ) -> Result<T, CallError>
    where
        F: FnMut(C) -> Fut,
        Fut: std::future::Future<Output = Result<T, ArchiveClientError>>,
    {
        let (client, id, kept) = self
            .connect(endpoint, dials)
            .await
            .map_err(CallError::Dial)?;
        let started = Instant::now();
        let error = match call(client).await {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        if !connection_failed(&error) {
            return Err(CallError::Call(error));
        }
        self.discard(endpoint, id);
        if !kept || error.is_timeout() || started.elapsed() >= self.stale_failure {
            return Err(CallError::Call(error));
        }
        let (client, id, _) = self
            .connect(endpoint, dials)
            .await
            .map_err(CallError::Dial)?;
        call(client).await.map_err(|error| {
            if connection_failed(&error) {
                self.discard(endpoint, id);
            }
            CallError::Call(error)
        })
    }
}

/// One forwarded page's share of a scan's [`ScanStats`].
struct PageCost {
    started: Instant,
    entries: usize,
    asked: u32,
    has_more: bool,
    dials: u64,
    took: Duration,
    /// Attempts at this page that failed before one delivered it.
    failed_attempts: u64,
}

/// What a forwarded scan or listing cost so far, for the line its end logs.
#[derive(Clone, Copy)]
struct ScanStats {
    started: Instant,
    pages: u64,
    entries: u64,
    asked: u32,
    /// Pages with more to follow that held fewer entries than asked.
    short_pages: u64,
    dials: u64,
    page_time: Duration,
    slowest_page: Duration,
    failed_attempts: u64,
}

impl ScanStats {
    fn start(page: &PageCost) -> Self {
        Self {
            started: page.started,
            pages: 0,
            entries: 0,
            asked: page.asked,
            short_pages: 0,
            dials: 0,
            page_time: Duration::ZERO,
            slowest_page: Duration::ZERO,
            failed_attempts: 0,
        }
    }

    fn add(&mut self, page: &PageCost) {
        self.pages += 1;
        self.entries += page.entries as u64;
        self.asked = page.asked;
        if page.has_more && page.entries < page.asked as usize {
            self.short_pages += 1;
        }
        self.dials += page.dials;
        self.page_time += page.took;
        self.slowest_page = self.slowest_page.max(page.took);
        self.failed_attempts += page.failed_attempts;
    }
}

/// Why a forwarded scan's end is a warning.
#[derive(Debug, PartialEq, Eq)]
enum ScanAnomaly {
    ShortPages,
    Slow,
}

impl ScanStats {
    fn anomaly(&self) -> Option<ScanAnomaly> {
        if self.short_pages > 0 {
            Some(ScanAnomaly::ShortPages)
        } else if self.slowest_page > SLOW_PAGE {
            Some(ScanAnomaly::Slow)
        } else {
            None
        }
    }
}

/// The one line a forwarded scan or listing logs at its end: info, or a warn
/// when a page was slow or its pages came back smaller than asked.
fn log_scan_end(
    what: &str,
    application: &[u8; 32],
    endpoint: &str,
    served_by: &str,
    stats: &ScanStats,
) {
    let elapsed = stats.started.elapsed();
    let pages = stats.pages.max(1);
    let mean_per_page = format!("{:.1}", stats.entries as f64 / pages as f64);
    let mean_page_ms = (stats.page_time.as_millis() / u128::from(pages)) as u64;
    let slowest_page_ms = stats.slowest_page.as_millis() as u64;
    let elapsed_s = format!("{:.1}", elapsed.as_secs_f64());
    let application = hex::encode(application);
    let (pages, coins, asked_per_page, dials, failed_attempts) = (
        stats.pages,
        stats.entries,
        stats.asked,
        stats.dials,
        stats.failed_attempts,
    );
    match stats.anomaly() {
        Some(ScanAnomaly::ShortPages) => tracing::warn!(
            %application, %endpoint, served_by, pages, coins, asked_per_page,
            %mean_per_page, short_pages = stats.short_pages, dials, failed_attempts,
            mean_page_ms, slowest_page_ms, %elapsed_s, scope = "peer",
            "forwarded {what} got pages smaller than asked: the serving peer runs a build without full pages; nothing to fix on this node"
        ),
        Some(ScanAnomaly::Slow) => tracing::warn!(
            %application, %endpoint, served_by, pages, coins, asked_per_page,
            %mean_per_page, dials, failed_attempts, mean_page_ms, slowest_page_ms, %elapsed_s,
            "forwarded {what} had a page over 10 s: a high mean_page_ms means a slow serving peer or path, a low one a single slow page; dials or failed_attempts near pages means this node's connections to it keep failing"
        ),
        None => tracing::info!(
            %application, %endpoint, served_by, pages, coins, asked_per_page,
            %mean_per_page, dials, failed_attempts, mean_page_ms, slowest_page_ms, %elapsed_s,
            "forwarded {what} finished"
        ),
    }
}

fn lost_pin() -> String {
    "the peer serving this scan is no longer pinned; restart the scan".into()
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
enum ScanKind {
    Coins,
    Escrows,
}

type ScanKey = (ScanKind, [u8; 32], [u8; 32]);

/// The endpoint serving a paged scan, and the scan's cost so far.
struct PinnedScan {
    endpoint: ReadEndpoint,
    used: Instant,
    stats: ScanStats,
}

type PeerInfoCache = Arc<parking_lot::RwLock<HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>>>;

/// Where a forwarded read is sent: a covering prover's endpoint, which must
/// answer as that prover, or an archive's (`peer` unset: the pool pins the
/// archives whose identity it knows).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct ReadEndpoint {
    addr: String,
    peer: Option<quil_p2p::PeerId>,
}

impl ReadEndpoint {
    fn archive(addr: String) -> Self {
        Self { addr, peer: None }
    }
}

impl std::fmt::Display for ReadEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.addr)
    }
}

/// An archive's endpoint, for tests.
#[cfg(test)]
impl From<&str> for ReadEndpoint {
    fn from(addr: &str) -> Self {
        Self::archive(addr.into())
    }
}

/// Reads an application's coins from whichever node holds it.
pub struct PeerCoinReader {
    peer_info_cache: PeerInfoCache,
    archive_pool: Arc<quil_rpc::ArchiveEndpointPool>,
    /// Decides which peers count as covering nodes ([`Self::covering_endpoints`]).
    prover_registry: Option<Arc<dyn quil_types::consensus::ProverRegistry>>,
    /// Kept connections, dialed with the `:8340` mTLS identity.
    connections: ReadConnections<quil_rpc::ArchiveClient>,
    network: u8,
    /// Scan snapshot → the endpoint that served it. A paged scan is pinned to
    /// one peer's snapshot, so continuing it anywhere else would restart the
    /// scan; the cursor means nothing to another node's store.
    served_by: parking_lot::Mutex<HashMap<ScanKey, PinnedScan>>,
    /// `(application, owner)` → the cost of a legacy listing in progress
    /// and its last page's time.
    listings: parking_lot::Mutex<HashMap<([u8; 32], [u8; 32]), (ScanStats, Instant)>>,
    /// `(budget, delay)` of each forwarded read's retries.
    read_retry: (Duration, Duration),
    /// The most one peer gets for one attempt at a coin page.
    page_attempt: Duration,
    /// Endpoint → when its last decline was logged at info.
    declines_logged: parking_lot::Mutex<HashMap<String, Instant>>,
}

impl PeerCoinReader {
    pub fn new(
        peer_info_cache: PeerInfoCache,
        archive_pool: Arc<quil_rpc::ArchiveEndpointPool>,
        falcon_key: Vec<u8>,
        network: u8,
    ) -> Self {
        let falcon_key: Arc<[u8]> = falcon_key.into();
        // A covering prover's endpoint must answer as that prover, so a
        // record cannot name another node's address and have that node
        // answer for it; an archive's is dialed as the pool pins it.
        let dial: Dial<quil_rpc::ArchiveClient> = Arc::new(move |endpoint: ReadEndpoint| {
            let falcon_key = falcon_key.clone();
            Box::pin(async move {
                let addr = endpoint.addr.as_str();
                match endpoint.peer {
                    Some(peer) => {
                        quil_rpc::ArchiveClient::connect_peer(addr, &falcon_key, peer).await
                    }
                    None => quil_rpc::ArchiveClient::connect_mtls(addr, &falcon_key).await,
                }
            })
        });
        Self {
            peer_info_cache,
            archive_pool,
            prover_registry: None,
            connections: ReadConnections::new(dial, CONNECTION_IDLE, MAX_CONNECTIONS),
            network,
            served_by: parking_lot::Mutex::new(HashMap::new()),
            listings: parking_lot::Mutex::new(HashMap::new()),
            read_retry: (READ_RETRY_BUDGET, READ_RETRY_DELAY),
            page_attempt: PAGE_ATTEMPT,
            declines_logged: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    /// The registry that decides which peers count as covering nodes: the
    /// registered provers serving the application's shards. Without one, or
    /// until it has loaded, reads go to archives only.
    pub fn with_prover_registry(
        mut self,
        registry: Arc<dyn quil_types::consensus::ProverRegistry>,
    ) -> Self {
        self.prover_registry = Some(registry);
        self
    }

    #[cfg(test)]
    fn with_read_retry(mut self, budget: Duration, delay: Duration) -> Self {
        self.read_retry = (budget, delay);
        self
    }

    #[cfg(test)]
    fn with_page_attempt(mut self, attempt: Duration) -> Self {
        self.page_attempt = attempt;
        self
    }

    #[cfg(test)]
    fn with_dial(mut self, dial: Dial<quil_rpc::ArchiveClient>) -> Self {
        self.connections = ReadConnections::new(dial, CONNECTION_IDLE, MAX_CONNECTIONS);
        self
    }

    /// Endpoints of registered provers serving a complete partition of
    /// `domain`, each to be dialed as its prover. A child shard alone cannot
    /// answer an application-wide scan. Group by endpoint within each peer:
    /// cluster workers on different endpoints do not share stores. A shard
    /// counts only when the record's signer holds an allocation on it,
    /// confirmed and not left: any key can sign a PeerInfo claiming an
    /// application, and the endpoints sorting first used to be asked first.
    fn covering_endpoints(&self, domain: &[u8; 32]) -> Vec<ReadEndpoint> {
        let Some(registry) = self
            .prover_registry
            .as_deref()
            .filter(|registry| registry.initial_load_complete())
        else {
            return Vec::new();
        };
        let cache = self.peer_info_cache.read();
        // A record's claimed shards on one endpoint: filter and decoded path.
        type ClaimedShards<'a> = Vec<(&'a [u8], Vec<bool>)>;
        // Per record, the shards (filter and path) each endpoint names. A
        // set of paths covers no less with more paths in it, so an endpoint
        // whose every claimed shard does not cover is dropped here, before
        // the registry is asked about it.
        let mut claims = Vec::new();
        for info in cache.values() {
            let mut by_endpoint: HashMap<String, ClaimedShards<'_>> = HashMap::new();
            for reach in &info.reachability {
                // A shard partitions a 256-bit data address. Reject longer
                // advertised paths before decoding or recursive coverage work.
                if !reach.filter.starts_with(domain.as_slice()) || reach.filter.len() > 32 + 2 + 32
                {
                    continue;
                }
                let Some((_, path)) = quil_forest::decode_shard_filter_or_root(&reach.filter, 32)
                else {
                    continue;
                };
                for endpoint in reach.stream_multiaddrs.iter().filter_map(|ma| {
                    crate::util::multiaddr::archive_multiaddr_to_host_port(ma, self.network)
                }) {
                    by_endpoint
                        .entry(endpoint)
                        .or_default()
                        .push((reach.filter.as_slice(), path.clone()));
                }
            }
            by_endpoint.retain(|_, shards| covers(shards.iter()));
            if !by_endpoint.is_empty() {
                claims.push((info, by_endpoint));
            }
        }
        // Peer ID → the claimed shards its prover serves, asked once per shard.
        let filters: HashSet<&[u8]> = claims
            .iter()
            .flat_map(|(_, by_endpoint)| by_endpoint.values().flatten())
            .map(|(filter, _)| *filter)
            .collect();
        let mut served: HashMap<Vec<u8>, HashSet<&[u8]>> = HashMap::new();
        for filter in filters {
            for prover in registry.get_provers(filter).unwrap_or_default() {
                if super::peer_info_file::serves(&prover, filter) {
                    served
                        .entry(quil_p2p::peer_id_from_falcon_pubkey(&prover.public_key))
                        .or_default()
                        .insert(filter);
                }
            }
        }
        let mut endpoints = Vec::new();
        for (info, by_endpoint) in claims {
            let Some(filters) = served.get(&info.peer_id) else {
                continue;
            };
            let Ok(peer) = quil_p2p::PeerId::from_bytes(&info.peer_id) else {
                continue;
            };
            for (addr, shards) in by_endpoint {
                if covers(shards.iter().filter(|(filter, _)| filters.contains(filter))) {
                    endpoints.push(ReadEndpoint {
                        addr,
                        peer: Some(peer),
                    });
                }
            }
        }
        endpoints.sort();
        endpoints.dedup();
        endpoints
    }

    /// Bounded attempts in preference order, with room reserved for archives
    /// even when every advertised covering peer is stale or unreachable. An
    /// archive already asked as a covering node (its address, answering as
    /// the identity the pool pins for it) is not asked twice; one whose
    /// address a covering record merely names still is.
    async fn read_endpoints(&self, domain: &[u8; 32]) -> Vec<ReadEndpoint> {
        let mut endpoints: Vec<_> = self
            .covering_endpoints(domain)
            .into_iter()
            .take(MAX_ATTEMPTS)
            .collect();
        let mut seen: HashSet<String> = endpoints
            .iter()
            .filter(|endpoint| {
                let pinned = quil_rpc::archive_client::pinned_archive_peer(&endpoint.addr);
                endpoint.peer.is_some() && endpoint.peer == pinned
            })
            .map(|endpoint| endpoint.addr.clone())
            .collect();
        endpoints.extend(
            self.archive_pool
                .get_all()
                .await
                .into_iter()
                .filter(|endpoint| seen.insert(endpoint.clone()))
                .take(MAX_ATTEMPTS)
                .map(ReadEndpoint::archive),
        );
        endpoints
    }

    /// The coins a scan's last page asked for: a path that could not carry
    /// more once is not asked for more until the scan ends.
    fn pinned_page_entries(&self, kind: ScanKind, domain: [u8; 32], id: [u8; 32]) -> Option<u32> {
        self.served_by
            .lock()
            .get(&(kind, domain, id))
            .map(|pin| pin.stats.asked)
    }

    fn pinned_endpoint(
        &self,
        kind: ScanKind,
        domain: [u8; 32],
        id: [u8; 32],
    ) -> Option<ReadEndpoint> {
        let mut pins = self.served_by.lock();
        pins.retain(|_, pin| pin.used.elapsed() < SCAN_PIN_TTL);
        let pin = pins.get_mut(&(kind, domain, id))?;
        pin.used = Instant::now();
        Some(pin.endpoint.clone())
    }

    /// Pin the scan a page continues to `endpoint`, or end it with the page
    /// that has no more to follow; that returns the scan's cost.
    fn remember_scan(
        &self,
        kind: ScanKind,
        domain: [u8; 32],
        id: [u8; 32],
        endpoint: ReadEndpoint,
        page: &PageCost,
    ) -> Option<ScanStats> {
        let key = (kind, domain, id);
        let mut pins = self.served_by.lock();
        pins.retain(|_, pin| pin.used.elapsed() < SCAN_PIN_TTL);
        let mut stats = pins
            .get(&key)
            .map_or_else(|| ScanStats::start(page), |pin| pin.stats);
        stats.add(page);
        if !page.has_more {
            pins.remove(&key);
            return Some(stats);
        }
        if pins.len() >= MAX_PINNED_SCANS && !pins.contains_key(&key) {
            if let Some(oldest) = pins
                .iter()
                .min_by_key(|(_, pin)| pin.used)
                .map(|(key, _)| *key)
            {
                pins.remove(&oldest);
            }
        }
        pins.insert(
            key,
            PinnedScan {
                endpoint,
                used: Instant::now(),
                stats,
            },
        );
        None
    }

    /// Count a legacy listing's page; the last one returns the listing's
    /// cost. A continuation whose start this node did not see is not counted.
    fn listing_page(
        &self,
        domain: [u8; 32],
        owner: [u8; 32],
        first: bool,
        page: &PageCost,
    ) -> Option<ScanStats> {
        let key = (domain, owner);
        let mut listings = self.listings.lock();
        listings.retain(|_, (_, used)| used.elapsed() < SCAN_PIN_TTL);
        let mut stats = match listings.remove(&key) {
            _ if first => ScanStats::start(page),
            Some((stats, _)) => stats,
            None => return None,
        };
        stats.add(page);
        if !page.has_more {
            return Some(stats);
        }
        if listings.len() >= MAX_PINNED_SCANS {
            if let Some(oldest) = listings
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(key, _)| *key)
            {
                listings.remove(&oldest);
            }
        }
        listings.insert(key, (stats, Instant::now()));
        None
    }

    /// Log a peer's decline of a coin scan: at info once per endpoint per
    /// [`DECLINE_LOG_INTERVAL`], at debug otherwise.
    fn log_decline(&self, endpoint: &str, domain: &[u8; 32], reason: &str) {
        let now = Instant::now();
        let first = {
            let mut logged = self.declines_logged.lock();
            logged.retain(|_, at| now.duration_since(*at) < DECLINE_LOG_INTERVAL);
            match logged.entry(endpoint.to_string()) {
                std::collections::hash_map::Entry::Occupied(_) => false,
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(now);
                    true
                }
            }
        };
        let reason = bounded_reason(reason);
        if first {
            tracing::info!(
                %endpoint, application = %hex::encode(domain), %reason,
                "remote coin scan: peer declined; asking the next covering node or archive"
            );
        } else {
            tracing::debug!(%endpoint, application = %hex::encode(domain), %reason, "remote coin scan: peer declined");
        }
    }

    /// Ask one endpoint for a page. `Err` is that peer's reason for not
    /// answering (it does not serve the application, could not be reached,
    /// or sent a malformed page): try the next one. It is never read as
    /// "the application is empty". An attempt ends after `page_attempt` or at
    /// `deadline`, whichever comes first.
    #[allow(clippy::too_many_arguments)] // the wire request, its bounds and the dial count
    async fn page_from(
        &self,
        endpoint: &ReadEndpoint,
        domain: &[u8; 32],
        snapshot_id: Option<&[u8; 32]>,
        after: Option<&[u8; 32]>,
        max_coins: u32,
        dials: &AtomicU64,
        deadline: Instant,
    ) -> Result<CoinPageData, Decline> {
        let attempt = self
            .page_attempt
            .min(deadline.saturating_duration_since(Instant::now()));
        let call = self.connections.call(endpoint, dials, |mut client| {
            let request = (
                domain.to_vec(),
                snapshot_id.map(|id| id.to_vec()).unwrap_or_default(),
                after.map(|a| a.to_vec()).unwrap_or_default(),
            );
            async move {
                client
                    .list_shard_coins(request.0, request.1, request.2, max_coins)
                    .await
            }
        });
        let page = match tokio::time::timeout(attempt, call).await {
            Ok(Ok(page)) => page,
            Ok(Err(CallError::Dial(error))) => {
                return Err(Decline {
                    reason: format!("dial failed: {}", with_causes(&error)),
                    transfer: false,
                })
            }
            Ok(Err(CallError::Call(error))) => {
                let transfer = connection_failed(&error);
                let reason = match &error {
                    ArchiveClientError::Rpc(status) => status_reason(status),
                    other => with_causes(other),
                };
                return Err(Decline { reason, transfer });
            }
            Err(_) => {
                return Err(Decline {
                    reason: format!(
                        "page of {max_coins} coins not delivered in {:.0} s",
                        attempt.as_secs_f64()
                    ),
                    transfer: true,
                })
            }
        };
        let malformed = || Decline {
            reason: "malformed coin page".to_string(),
            transfer: false,
        };
        let network: [u8; 32] = page.network.try_into().map_err(|_| malformed())?;
        let snapshot: [u8; 32] = page.snapshot_id.try_into().map_err(|_| malformed())?;
        let coins = page
            .coins
            .into_iter()
            .map(|c| {
                Some(CoinData {
                    address: c.address.try_into().ok()?,
                    frame_number: c.frame_number,
                    position: c.position,
                    owner: c.owner,
                    commitment: c.commitment,
                    memo: c.memo,
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(malformed)?;
        let cursor = if page.cursor.is_empty() {
            None
        } else {
            Some(page.cursor.try_into().map_err(|_| malformed())?)
        };
        Ok(CoinPageData {
            network,
            snapshot_id: snapshot,
            root_record: page.root_record,
            coins,
            cursor,
            has_more: page.has_more,
        })
    }

    /// Coin witnesses for `domain` from a node that holds it — the membership
    /// paths a spend needs. Same preference order as the scan. The witnesses
    /// are checked by the wallet against the returned root, and a spend's
    /// witness must match a root the network retains, so a peer cannot make
    /// one up.
    pub async fn coin_witnesses(
        &self,
        domain: [u8; 32],
        addresses: Vec<[u8; 32]>,
    ) -> Option<quil_types::store::CoinWitnessBundle> {
        let (budget, delay) = self.read_retry;
        retry_within(budget, delay, || {
            self.coin_witnesses_once(domain, &addresses)
        })
        .await
    }

    async fn coin_witnesses_once(
        &self,
        domain: [u8; 32],
        addresses: &[[u8; 32]],
    ) -> Option<quil_types::store::CoinWitnessBundle> {
        let dials = AtomicU64::new(0);
        for endpoint in self.read_endpoints(&domain).await {
            let bundle = match self
                .connections
                .call(&endpoint, &dials, |mut client| {
                    let addresses = addresses.iter().map(|a| a.to_vec()).collect();
                    async move {
                        client
                            .get_shard_coin_witnesses(domain.to_vec(), addresses)
                            .await
                    }
                })
                .await
            {
                Ok(bundle) => bundle,
                Err(CallError::Dial(_)) => continue,
                Err(CallError::Call(error)) => {
                    tracing::debug!(%endpoint, %error, "remote coin witnesses: peer declined");
                    continue;
                }
            };
            let Ok(network) = <[u8; 32]>::try_from(bundle.network) else {
                continue;
            };
            let Ok(depth) = u8::try_from(bundle.depth) else {
                continue;
            };
            let witnesses: Option<Vec<_>> = bundle
                .witnesses
                .into_iter()
                .map(|w| {
                    Some(quil_types::store::CoinWitnessData {
                        address: w.address.try_into().ok()?,
                        found: w.found,
                        siblings: w.siblings,
                        right: w.right,
                    })
                })
                .collect();
            let Some(witnesses) = witnesses else { continue };
            return Some(quil_types::store::CoinWitnessBundle {
                network,
                root_record: bundle.root_record,
                depth,
                witnesses,
            });
        }
        None
    }

    /// One vertex of `domain` from a node that holds it, as `(present, blob)`.
    /// Same preference order as the coin scan. The wallet reads spent markers
    /// this way, so a coin scan that forwards is useless without it.
    pub async fn vertex(&self, domain: [u8; 32], data_address: Vec<u8>) -> Option<(bool, Vec<u8>)> {
        let (budget, delay) = self.read_retry;
        retry_within(budget, delay, || self.vertex_once(domain, &data_address)).await
    }

    async fn vertex_once(&self, domain: [u8; 32], data_address: &[u8]) -> Option<(bool, Vec<u8>)> {
        let mut vertex_id = domain.to_vec();
        vertex_id.extend_from_slice(data_address);
        let dials = AtomicU64::new(0);
        for endpoint in self.read_endpoints(&domain).await {
            match self
                .connections
                .call(&endpoint, &dials, |mut client| {
                    let vertex_id = vertex_id.clone();
                    async move { client.get_shard_vertex(vertex_id).await }
                })
                .await
            {
                Ok(Some(blob)) => return Some((true, blob)),
                // The peer holds the application and has no such vertex: a real
                // answer (an unspent coin's marker is absent), not a miss.
                Ok(None) => return Some((false, Vec::new())),
                Err(CallError::Dial(_)) => {}
                Err(CallError::Call(error)) => {
                    tracing::debug!(%endpoint, %error, "remote vertex read: peer declined");
                }
            }
        }
        None
    }

    /// One page of up to `max_coins` of `domain`'s coins from a node that
    /// holds it: covering nodes first, an archive last. `Err` when nobody
    /// answered, with the peers' reasons; the caller then reports that this
    /// node cannot serve the application, never an empty page.
    pub async fn coin_page(
        &self,
        domain: [u8; 32],
        snapshot_id: Option<[u8; 32]>,
        after: Option<[u8; 32]>,
        max_coins: u32,
    ) -> Result<CoinPageData, String> {
        // Continuing a scan goes back to the peer whose snapshot it names; no
        // retry brings back a pin that is gone.
        if let Some(id) = snapshot_id {
            self.pinned_endpoint(ScanKind::Coins, domain, id)
                .ok_or_else(lost_pin)?;
        }
        let started = Instant::now();
        let dials = AtomicU64::new(0);
        let (budget, delay) = self.read_retry;
        let mut entries = snapshot_id
            .and_then(|id| self.pinned_page_entries(ScanKind::Coins, domain, id))
            .map_or(max_coins, |asked| asked.min(max_coins));
        let (attempts_until, deadline) = (started + budget, started + budget + self.page_attempt);
        let mut failed_attempts = 0;
        let (page, endpoint) = loop {
            let refusal = match self
                .coin_page_once(domain, snapshot_id, after, entries, &dials, deadline)
                .await
            {
                Ok(page) => break page,
                Err(refusal) => refusal,
            };
            failed_attempts += 1;
            if refusal.transfer && smaller_page(entries) < entries {
                entries = smaller_page(entries);
                tracing::info!(
                    application = %hex::encode(domain), entries,
                    reason = %bounded_reason(&refusal.reasons),
                    "forwarded coin scan: the path to the serving peer did not carry the page; \
                     asking for fewer coins a page for the rest of this scan"
                );
            }
            if Instant::now() + delay > attempts_until {
                return Err(self.page_given_up(
                    domain,
                    snapshot_id,
                    (failed_attempts, entries, started),
                    refusal.reasons,
                ));
            }
            tokio::time::sleep(delay).await;
        };
        // A rootless answer is final and pins nothing.
        let Some(endpoint) = endpoint else {
            return Ok(page);
        };
        let cost = PageCost {
            started,
            entries: page.coins.len(),
            asked: entries,
            has_more: page.has_more,
            dials: dials.load(Ordering::Relaxed),
            took: started.elapsed(),
            failed_attempts,
        };
        if let Some(stats) = self.remember_scan(
            ScanKind::Coins,
            domain,
            page.snapshot_id,
            endpoint.clone(),
            &cost,
        ) {
            let served_by = if self.covering_endpoints(&domain).contains(&endpoint) {
                "covering"
            } else {
                "archive"
            };
            log_scan_end("coin scan", &domain, &endpoint.addr, served_by, &stats);
        }
        Ok(page)
    }

    /// The refusal for a page no attempt delivered, and the line it logs. The
    /// wallet may ask for the page again: the scan and its pin stay as they
    /// were, but for the smaller page size it should start from.
    fn page_given_up(
        &self,
        domain: [u8; 32],
        snapshot_id: Option<[u8; 32]>,
        (attempts, entries, started): (u64, u32, Instant),
        reasons: String,
    ) -> String {
        let elapsed_s = format!("{:.1}", started.elapsed().as_secs_f64());
        let pin = snapshot_id.and_then(|id| {
            self.served_by
                .lock()
                .get_mut(&(ScanKind::Coins, domain, id))
                .map(|pin| {
                    pin.stats.asked = entries;
                    (pin.endpoint.clone(), pin.stats)
                })
        });
        let application = hex::encode(domain);
        let reason = bounded_reason(&reasons);
        match pin {
            Some((endpoint, stats)) => {
                tracing::warn!(
                    %application, %endpoint, attempts, entries, %elapsed_s, %reason,
                    pages_done = stats.pages, coins_done = stats.entries,
                    scope = "peer or path",
                    "forwarded coin scan: no attempt delivered this page; its snapshot is on this peer alone, so no other is asked. The wallet may ask again: check this node's link to the peer if it recurs"
                );
                format!(
                    "{reasons} (the scan is pinned to the one peer holding its snapshot, {attempts} attempts in {elapsed_s} s, the last for {entries} coins)"
                )
            }
            None => {
                tracing::warn!(
                    %application, attempts, entries, %elapsed_s, %reason, scope = "peer or path",
                    "forwarded coin scan: no peer delivered its first page. The wallet may ask again: check this node's link to the peers if it recurs"
                );
                reasons
            }
        }
    }

    /// A page and the endpoint that served it; `None` for a rootless answer.
    async fn coin_page_once(
        &self,
        domain: [u8; 32],
        snapshot_id: Option<[u8; 32]>,
        after: Option<[u8; 32]>,
        max_coins: u32,
        dials: &AtomicU64,
        deadline: Instant,
    ) -> Result<(CoinPageData, Option<ReadEndpoint>), PageRefusal> {
        let endpoints = match snapshot_id {
            Some(id) => vec![self
                .pinned_endpoint(ScanKind::Coins, domain, id)
                .ok_or_else(|| PageRefusal {
                    reasons: lost_pin(),
                    transfer: false,
                })?],
            None => self.read_endpoints(&domain).await,
        };
        let mut declines = Declines::default();
        let mut transfer = false;
        // A peer's answer that the application has no coin root yet is held
        // back while another peer may still list coins: a lagging or
        // withholding peer must not hide what another can show.
        let mut rootless = None;
        for endpoint in endpoints {
            match self
                .page_from(
                    &endpoint,
                    &domain,
                    snapshot_id.as_ref(),
                    after.as_ref(),
                    max_coins,
                    dials,
                    deadline,
                )
                .await
            {
                Ok(page) if page.root_record.is_empty() => {
                    if rootless.is_none() {
                        rootless = Some((page, None));
                    }
                }
                Ok(page) => {
                    tracing::debug!(
                        %endpoint, application = %hex::encode(domain),
                        "served a coin page from a covering node or archive"
                    );
                    return Ok((page, Some(endpoint)));
                }
                Err(decline) => {
                    self.log_decline(&endpoint.addr, &domain, &decline.reason);
                    declines.push(&decline.reason);
                    transfer |= decline.transfer;
                }
            }
        }
        rootless.ok_or_else(|| PageRefusal {
            reasons: declines.summary(),
            transfer,
        })
    }

    /// One page of `owner`'s legacy coins from an archive: only an archive
    /// keeps the owner index. The legacy set never changes, so a cursor means
    /// the same on every archive and no endpoint is pinned.
    pub async fn legacy_coins(
        &self,
        domain: [u8; 32],
        owner: [u8; 32],
        after: Option<[u8; 32]>,
    ) -> Option<quil_types::store::LegacyCoinPageData> {
        let started = Instant::now();
        let dials = AtomicU64::new(0);
        let (budget, delay) = self.read_retry;
        let (page, endpoint) = retry_within(budget, delay, || {
            self.legacy_coins_once(domain, owner, after, &dials)
        })
        .await?;
        let cost = PageCost {
            started,
            entries: page.coins.len(),
            asked: quil_types::store::MAX_LEGACY_COINS_PER_PAGE as u32,
            has_more: page.has_more,
            dials: dials.load(Ordering::Relaxed),
            took: started.elapsed(),
            failed_attempts: 0,
        };
        if let Some(stats) = self.listing_page(domain, owner, after.is_none(), &cost) {
            log_scan_end("legacy listing", &domain, &endpoint, "archive", &stats);
        }
        Some(page)
    }

    /// A page and the archive that served it.
    async fn legacy_coins_once(
        &self,
        domain: [u8; 32],
        owner: [u8; 32],
        after: Option<[u8; 32]>,
        dials: &AtomicU64,
    ) -> Option<(quil_types::store::LegacyCoinPageData, String)> {
        for endpoint in self
            .archive_pool
            .get_all()
            .await
            .into_iter()
            .take(MAX_ATTEMPTS)
            .map(ReadEndpoint::archive)
        {
            let page = match self
                .connections
                .call(&endpoint, dials, |mut client| {
                    let after = after.map(|a| a.to_vec()).unwrap_or_default();
                    async move {
                        client
                            .list_shard_legacy_coins(domain.to_vec(), owner.to_vec(), after)
                            .await
                    }
                })
                .await
            {
                Ok(page) => page,
                Err(CallError::Dial(_)) => continue,
                Err(CallError::Call(error)) => {
                    tracing::debug!(%endpoint, %error, "remote legacy coins: archive declined");
                    continue;
                }
            };
            let decoded = (|| {
                Some(quil_types::store::LegacyCoinPageData {
                    coins: page
                        .coins
                        .into_iter()
                        .map(|coin| {
                            Some(quil_types::store::LegacyCoinData {
                                address: coin.address.try_into().ok()?,
                                amount: u128::from_le_bytes(coin.amount.try_into().ok()?),
                                origin: coin.origin.try_into().ok()?,
                                shielded: coin.shielded,
                            })
                        })
                        .collect::<Option<Vec<_>>>()?,
                    cursor: if page.cursor.is_empty() {
                        None
                    } else {
                        Some(page.cursor.try_into().ok()?)
                    },
                    has_more: page.has_more,
                })
            })();
            if let Some(page) = decoded {
                return Some((page, endpoint.addr));
            }
        }
        None
    }

    pub async fn escrow_page(
        &self,
        domain: [u8; 32],
        snapshot_id: Option<[u8; 32]>,
        after: Option<[u8; 32]>,
        max_escrows: u32,
    ) -> Option<EscrowPageData> {
        if let Some(id) = snapshot_id {
            self.pinned_endpoint(ScanKind::Escrows, domain, id)?;
        }
        let (budget, delay) = self.read_retry;
        retry_within(budget, delay, || {
            self.escrow_page_once(domain, snapshot_id, after, max_escrows)
        })
        .await
    }

    async fn escrow_page_once(
        &self,
        domain: [u8; 32],
        snapshot_id: Option<[u8; 32]>,
        after: Option<[u8; 32]>,
        max_escrows: u32,
    ) -> Option<EscrowPageData> {
        let endpoints = match snapshot_id {
            Some(id) => vec![self.pinned_endpoint(ScanKind::Escrows, domain, id)?],
            None => self.read_endpoints(&domain).await,
        };
        let started = Instant::now();
        let dials = AtomicU64::new(0);
        for endpoint in endpoints {
            let page = match self
                .connections
                .call(&endpoint, &dials, |mut client| {
                    let request = (
                        snapshot_id.map(|id| id.to_vec()).unwrap_or_default(),
                        after.map(|id| id.to_vec()).unwrap_or_default(),
                    );
                    async move {
                        client
                            .list_shard_escrows(domain.to_vec(), request.0, request.1, max_escrows)
                            .await
                    }
                })
                .await
            {
                Ok(page) => page,
                Err(CallError::Dial(_)) => continue,
                Err(CallError::Call(error)) => {
                    tracing::debug!(%endpoint, %error, "remote escrow scan: peer declined");
                    continue;
                }
            };
            let decoded = (|| {
                Some(EscrowPageData {
                    network: page.network.try_into().ok()?,
                    snapshot_id: page.snapshot_id.try_into().ok()?,
                    escrows: page
                        .escrows
                        .into_iter()
                        .map(|e| Some((e.address.try_into().ok()?, e.raw_data)))
                        .collect::<Option<Vec<_>>>()?,
                    cursor: if page.cursor.is_empty() {
                        None
                    } else {
                        Some(page.cursor.try_into().ok()?)
                    },
                    has_more: page.has_more,
                })
            })();
            if let Some(page) = decoded {
                // Escrow scans keep their pin; their cost is not logged.
                let cost = PageCost {
                    started,
                    entries: page.escrows.len(),
                    asked: max_escrows,
                    has_more: page.has_more,
                    dials: dials.load(Ordering::Relaxed),
                    took: started.elapsed(),
                    failed_attempts: 0,
                };
                self.remember_scan(ScanKind::Escrows, domain, page.snapshot_id, endpoint, &cost);
                return Some(page);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::global::app_shard_service_server::{
        AppShardService, AppShardServiceServer,
    };
    use quil_types::proto::global::{
        AppShardFrameResponse, AppShardProposalResponse, GetAppShardFrameRequest,
        GetAppShardProposalRequest, GetShardCoinWitnessesRequest, GetShardCoinWitnessesResponse,
        GetShardOutgoingHistoryRequest, GetShardOutgoingHistoryResponse, GetShardVertexRequest,
        GetShardVertexResponse, ListLegacyCoinsRequest, ListLegacyCoinsResponse,
        ListShardCoinsRequest, ListShardCoinsResponse, ListShardEscrowsResponse, ShardCoin,
    };
    use std::slice::from_ref;
    use tonic::{Request, Response, Status};

    fn page(has_more: bool) -> PageCost {
        PageCost {
            started: Instant::now(),
            entries: 1,
            asked: 1,
            has_more,
            dials: 0,
            took: Duration::ZERO,
            failed_attempts: 0,
        }
    }

    /// A peer serving one application: `pages` coin pages of two coins, a
    /// vertex and an empty legacy listing.
    struct Peer {
        pages: u8,
        /// Sizes a page by the request, with coins of this many memo bytes;
        /// zero serves pages of two empty coins as a peer without the field.
        memo_bytes: usize,
        /// The sizes asked for.
        asked: Arc<parking_lot::Mutex<Vec<u32>>>,
        /// A request for more coins than this is never answered.
        stall_above: u32,
    }

    impl Peer {
        fn of_pages(pages: u8) -> Self {
            Self {
                pages,
                memo_bytes: 0,
                asked: Arc::default(),
                stall_above: u32::MAX,
            }
        }
    }

    #[tonic::async_trait]
    impl AppShardService for Peer {
        async fn get_app_shard_frame(
            &self,
            _: Request<GetAppShardFrameRequest>,
        ) -> Result<Response<AppShardFrameResponse>, Status> {
            Err(Status::unimplemented("not served"))
        }

        async fn get_app_shard_proposal(
            &self,
            _: Request<GetAppShardProposalRequest>,
        ) -> Result<Response<AppShardProposalResponse>, Status> {
            Err(Status::unimplemented("not served"))
        }

        async fn list_shard_coins(
            &self,
            request: Request<ListShardCoinsRequest>,
        ) -> Result<Response<ListShardCoinsResponse>, Status> {
            let request = request.into_inner();
            let after = request.after;
            self.asked.lock().push(request.max_coins);
            if request.max_coins > self.stall_above {
                std::future::pending::<()>().await;
            }
            let start = after.first().map_or(0, |last| last + 1);
            let step = if self.memo_bytes == 0 {
                2
            } else {
                request.max_coins as u8
            };
            let end = start.saturating_add(step).min(2 * self.pages);
            Ok(Response::new(ListShardCoinsResponse {
                network: vec![0; 32],
                snapshot_id: vec![7; 32],
                root_record: vec![1],
                coins: (start..end)
                    .map(|i| ShardCoin {
                        address: vec![i; 32],
                        memo: vec![i; self.memo_bytes],
                        ..Default::default()
                    })
                    .collect(),
                cursor: vec![end - 1; 32],
                has_more: end < 2 * self.pages,
            }))
        }

        async fn list_shard_legacy_coins(
            &self,
            _: Request<ListLegacyCoinsRequest>,
        ) -> Result<Response<ListLegacyCoinsResponse>, Status> {
            Ok(Response::new(ListLegacyCoinsResponse::default()))
        }

        async fn get_shard_coin_witnesses(
            &self,
            _: Request<GetShardCoinWitnessesRequest>,
        ) -> Result<Response<GetShardCoinWitnessesResponse>, Status> {
            Err(Status::unimplemented("not served"))
        }

        async fn list_shard_escrows(
            &self,
            _: Request<ListShardCoinsRequest>,
        ) -> Result<Response<ListShardEscrowsResponse>, Status> {
            Err(Status::unimplemented("not served"))
        }

        async fn get_shard_vertex(
            &self,
            _: Request<GetShardVertexRequest>,
        ) -> Result<Response<GetShardVertexResponse>, Status> {
            Ok(Response::new(GetShardVertexResponse {
                found: true,
                blob: vec![1],
            }))
        }

        async fn get_shard_outgoing_history(
            &self,
            _: Request<GetShardOutgoingHistoryRequest>,
        ) -> Result<Response<GetShardOutgoingHistoryResponse>, Status> {
            Err(Status::unimplemented("not served"))
        }
    }

    /// Serve [`Peer`] over plaintext on a local port; returns its endpoint
    /// and the count of connections it accepted.
    async fn serve_peer(pages: u8) -> (String, Arc<AtomicU64>) {
        serve(Peer::of_pages(pages)).await
    }

    async fn serve(peer: Peer) -> (String, Arc<AtomicU64>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let accepted = Arc::new(AtomicU64::new(0));
        let incoming = futures::stream::unfold(
            (listener, accepted.clone()),
            |(listener, accepted)| async move {
                let stream = listener.accept().await.map(|(stream, _)| {
                    accepted.fetch_add(1, Ordering::SeqCst);
                    stream
                });
                Some((stream, (listener, accepted)))
            },
        );
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(AppShardServiceServer::new(peer))
                .serve_with_incoming(Box::pin(incoming)),
        );
        (endpoint, accepted)
    }

    /// A wallet's balance on a node without coverage: every page of a coin
    /// scan, then a spent-marker vertex and a legacy listing, all forwarded
    /// to one peer. Each forwarded call dialed afresh, a PQNoise handshake
    /// per page; one connection now serves them all.
    #[tokio::test]
    async fn forwarded_reads_share_one_connection_per_endpoint() {
        let (endpoint, accepted) = serve_peer(5).await;
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(Duration::ZERO));
        pool.add(endpoint).await;
        let dials = Arc::new(AtomicU64::new(0));
        let dial: Dial<quil_rpc::ArchiveClient> = {
            let dials = dials.clone();
            Arc::new(move |endpoint: ReadEndpoint| {
                dials.fetch_add(1, Ordering::SeqCst);
                Box::pin(
                    async move { quil_rpc::ArchiveClient::connect_plaintext(&endpoint.addr).await },
                )
            })
        };
        let reader = PeerCoinReader::new(
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            pool,
            vec![0; 32],
            1,
        )
        .with_read_retry(Duration::ZERO, Duration::from_millis(1))
        .with_dial(dial);
        let domain = [3; 32];
        let (mut snapshot, mut after, mut pages, mut coins) = (None, None, 0, 0);
        loop {
            let page = reader
                .coin_page(domain, snapshot, after, 2)
                .await
                .expect("the peer serves every page");
            pages += 1;
            coins += page.coins.len();
            if !page.has_more {
                break;
            }
            snapshot = Some(page.snapshot_id);
            after = page.cursor;
        }
        assert_eq!((pages, coins), (5, 10));
        assert_eq!(
            reader.vertex(domain, vec![4; 32]).await,
            Some((true, vec![1]))
        );
        assert!(reader.legacy_coins(domain, [5; 32], None).await.is_some());
        assert_eq!(
            dials.load(Ordering::SeqCst),
            1,
            "one dial for 7 forwarded reads"
        );
        assert_eq!(accepted.load(Ordering::SeqCst), 1, "one connection");
        // The finished scan left no pin behind.
        assert!(reader.served_by.lock().is_empty());
    }

    fn closed() -> ArchiveClientError {
        ArchiveClientError::Rpc(Status::from_error(Box::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection closed",
        ))))
    }

    /// Connections numbered by dial, for the pool alone.
    fn numbered_connections(idle: Duration, capacity: usize) -> ReadConnections<Arc<u64>> {
        let dialed = AtomicU64::new(0);
        let dial: Dial<Arc<u64>> = Arc::new(move |_: ReadEndpoint| {
            let n = dialed.fetch_add(1, Ordering::SeqCst) + 1;
            Box::pin(async move { Ok(Arc::new(n)) })
        });
        ReadConnections::new(dial, idle, capacity)
    }

    #[tokio::test]
    async fn a_closed_connection_is_redialed_and_an_idle_one_dropped() {
        let idle = Duration::from_millis(300);
        let connections = numbered_connections(idle, 2);
        let dials = AtomicU64::new(0);
        let number = |client: Arc<u64>| async move { Ok::<_, ArchiveClientError>(*client) };
        assert_eq!(
            connections.call(&"a".into(), &dials, number).await.ok(),
            Some(1)
        );
        assert_eq!(
            connections.call(&"a".into(), &dials, number).await.ok(),
            Some(1)
        );
        // The peer closed connection 1 while it was kept: the call goes
        // again at once on a new one.
        let served = connections
            .call(&"a".into(), &dials, |client: Arc<u64>| async move {
                match *client {
                    1 => Err(closed()),
                    n => Ok(n),
                }
            })
            .await;
        assert_eq!(served.ok(), Some(2));
        // A refusal is the peer's answer, not a broken connection.
        let refused = connections
            .call(&"a".into(), &dials, |_| async {
                Err::<u64, _>(ArchiveClientError::Rpc(Status::not_found("no such coin")))
            })
            .await;
        assert!(matches!(refused, Err(CallError::Call(_))));
        assert_eq!(
            connections.call(&"a".into(), &dials, number).await.ok(),
            Some(2)
        );
        assert_eq!(dials.load(Ordering::SeqCst), 2);
        // Unused past the idle bound, the connection is released without
        // another call...
        let kept =
            Arc::downgrade(&connections.open.lock().by_endpoint[&ReadEndpoint::from("a")].client);
        tokio::time::sleep(idle * 3).await;
        assert!(connections.open.lock().by_endpoint.is_empty());
        assert!(kept.upgrade().is_none(), "the connection was dropped");
        // ...and the next call dials.
        assert_eq!(
            connections.call(&"a".into(), &dials, number).await.ok(),
            Some(3)
        );
        // At most `capacity` endpoints, least recently used dropped first.
        assert_eq!(
            connections.call(&"b".into(), &dials, number).await.ok(),
            Some(4)
        );
        assert_eq!(
            connections.call(&"a".into(), &dials, number).await.ok(),
            Some(3)
        );
        assert_eq!(
            connections.call(&"c".into(), &dials, number).await.ok(),
            Some(5)
        );
        let mut endpoints: Vec<_> = connections
            .open
            .lock()
            .by_endpoint
            .keys()
            .map(|endpoint| endpoint.addr.clone())
            .collect();
        endpoints.sort();
        assert_eq!(endpoints, vec!["a", "c"]);
        assert_eq!(dials.load(Ordering::SeqCst), 5);
    }

    /// The stats of a scan whose full pages took these times.
    fn stats_of_pages(pages: &[Duration]) -> ScanStats {
        let reader = PeerCoinReader::new(
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            Arc::new(quil_rpc::ArchiveEndpointPool::new(Duration::ZERO)),
            vec![],
            1,
        );
        let mut end = None;
        for (index, took) in pages.iter().enumerate() {
            end = reader.remember_scan(
                ScanKind::Coins,
                [1; 32],
                [2; 32],
                "peer".into(),
                &PageCost {
                    started: Instant::now(),
                    entries: 64,
                    asked: 64,
                    has_more: index + 1 < pages.len(),
                    dials: 0,
                    took: *took,
                    failed_attempts: 0,
                },
            );
        }
        end.expect("the last page ends the scan")
    }

    #[test]
    fn a_long_scan_of_quick_pages_ends_without_a_warning() {
        // A wallet of thousands of coins: minutes in total, under 3 s a page.
        let stats = stats_of_pages(&[Duration::from_millis(2_700); 51]);
        assert_eq!(stats.page_time, Duration::from_millis(137_700));
        assert_eq!(stats.anomaly(), None);
    }

    #[test]
    fn one_slow_page_warns_however_short_the_scan() {
        let quick = Duration::from_millis(100);
        assert_eq!(stats_of_pages(&[quick, SLOW_PAGE, quick]).anomaly(), None);
        let stats = stats_of_pages(&[quick, SLOW_PAGE + Duration::from_secs(1), quick]);
        assert_eq!(stats.slowest_page, Duration::from_secs(11));
        assert_eq!(stats.anomaly(), Some(ScanAnomaly::Slow));
    }

    #[test]
    fn a_scan_end_reports_its_cost_and_short_pages() {
        let reader = PeerCoinReader::new(
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            Arc::new(quil_rpc::ArchiveEndpointPool::new(Duration::ZERO)),
            vec![],
            1,
        );
        let cost = |entries, has_more, dials| PageCost {
            started: Instant::now(),
            entries,
            asked: 64,
            has_more,
            dials,
            took: Duration::from_millis(10),
            failed_attempts: 1,
        };
        let (domain, id) = ([1; 32], [2; 32]);
        assert!(reader
            .remember_scan(
                ScanKind::Coins,
                domain,
                id,
                "peer".into(),
                &cost(8, true, 1)
            )
            .is_none());
        let stats = reader
            .remember_scan(
                ScanKind::Coins,
                domain,
                id,
                "peer".into(),
                &cost(3, false, 0),
            )
            .expect("the last page ends the scan");
        assert_eq!(
            (stats.pages, stats.entries, stats.short_pages, stats.dials),
            (2, 11, 1, 1)
        );
        assert_eq!(stats.page_time, Duration::from_millis(20));
        assert_eq!(stats.failed_attempts, 2);
        assert_eq!(stats.anomaly(), Some(ScanAnomaly::ShortPages));
        let id = [3; 32];
        reader.remember_scan(
            ScanKind::Coins,
            domain,
            id,
            "peer".into(),
            &cost(64, true, 1),
        );
        let stats = reader
            .remember_scan(
                ScanKind::Coins,
                domain,
                id,
                "peer".into(),
                &cost(5, false, 0),
            )
            .unwrap();
        assert_eq!(stats.anomaly(), None);
        // A legacy listing counts from its first page; a continuation whose
        // start this node did not see is not counted.
        let owner = [4; 32];
        assert!(reader
            .listing_page(domain, owner, false, &cost(64, false, 0))
            .is_none());
        assert!(reader
            .listing_page(domain, owner, true, &cost(64, true, 1))
            .is_none());
        let stats = reader
            .listing_page(domain, owner, false, &cost(9, false, 0))
            .unwrap();
        assert_eq!((stats.pages, stats.entries), (2, 73));
        assert!(reader.listings.lock().is_empty());
    }

    fn peer(filter: Vec<u8>, addrs: Vec<String>) -> quil_p2p::CanonicalPeerInfo {
        quil_p2p::CanonicalPeerInfo {
            reachability: vec![quil_p2p::CanonicalReachability {
                filter,
                pubsub_multiaddrs: Vec::new(),
                stream_multiaddrs: addrs,
            }],
            ..Default::default()
        }
    }

    /// A registered prover's record naming `host` for each `claimed` shard,
    /// and its registry entry, serving the `served` shards.
    fn registered(
        seed: u8,
        claimed: &[Vec<u8>],
        served: &[Vec<u8>],
        host: &str,
    ) -> (
        quil_p2p::CanonicalPeerInfo,
        quil_types::consensus::ProverInfo,
    ) {
        use crate::master_node::peer_info_file::test_prover;
        use quil_types::consensus::ProverStatus;
        let public_key = vec![seed; 897];
        let info = quil_p2p::CanonicalPeerInfo {
            peer_id: quil_p2p::peer_id_from_falcon_pubkey(&public_key),
            public_key: public_key.clone(),
            reachability: claimed
                .iter()
                .map(|filter| quil_p2p::CanonicalReachability {
                    filter: filter.clone(),
                    pubsub_multiaddrs: Vec::new(),
                    stream_multiaddrs: vec![format!("/ip4/{host}/tcp/8340")],
                })
                .collect(),
            ..Default::default()
        };
        let mut prover = test_prover(&public_key, &[], ProverStatus::Active);
        prover.allocations = served
            .iter()
            .flat_map(|filter| test_prover(&public_key, filter, ProverStatus::Active).allocations)
            .collect();
        (info, prover)
    }

    /// A reader over `records`, whose provers the registry holds.
    fn reader_of(
        records: Vec<(
            quil_p2p::CanonicalPeerInfo,
            quil_types::consensus::ProverInfo,
        )>,
        pool: Arc<quil_rpc::ArchiveEndpointPool>,
    ) -> PeerCoinReader {
        let (cache, provers): (HashMap<_, _>, Vec<_>) = records
            .into_iter()
            .map(|(info, prover)| ((info.peer_id.clone(), info), prover))
            .unzip();
        PeerCoinReader::new(
            Arc::new(parking_lot::RwLock::new(cache)),
            pool,
            vec![0; 32],
            1,
        )
        .with_prover_registry(Arc::new(
            quil_engine::test_support::TestProverRegistry::with_provers(provers),
        ))
    }

    fn no_archives() -> Arc<quil_rpc::ArchiveEndpointPool> {
        Arc::new(quil_rpc::ArchiveEndpointPool::new(Duration::ZERO))
    }

    fn addrs(endpoints: Vec<ReadEndpoint>) -> Vec<String> {
        endpoints
            .into_iter()
            .map(|endpoint| endpoint.addr)
            .collect()
    }

    /// A partial holder or a peer covering a different application cannot
    /// answer an application-wide wallet read.
    #[test]
    fn covering_peers_are_selected_by_advertised_filter() {
        let domain = [0xAB; 32];
        let root = domain.to_vec();
        let other = [0xCD; 32].to_vec();
        let half = quil_forest::encode_shard_bit_path(&domain, &[false]);
        let reader = reader_of(
            vec![
                registered(1, from_ref(&root), from_ref(&root), "10.0.0.1"),
                registered(2, from_ref(&other), from_ref(&other), "10.0.0.2"),
                registered(3, from_ref(&half), from_ref(&half), "10.0.0.3"),
            ],
            no_archives(),
        );
        let endpoints = reader.covering_endpoints(&domain);
        assert_eq!(endpoints.len(), 1, "{endpoints:?}");
        assert!(endpoints[0].addr.contains("10.0.0.1"), "{endpoints:?}");
        // The dial must reach the prover whose record named the endpoint.
        let (info, _) = registered(1, &[], &[], "");
        assert_eq!(
            endpoints[0].peer,
            Some(quil_p2p::PeerId::from_bytes(&info.peer_id).unwrap())
        );
        // An application nobody advertises has no covering candidate; the
        // caller then falls back to archives, and failing those, refuses.
        assert!(reader.covering_endpoints(&[0xEE; 32]).is_empty());
    }

    /// Only a registered prover serving the shards it claims covers them:
    /// not an unregistered key, nor a prover only joining them or serving
    /// another; and without a registry, no peer covers anything.
    #[test]
    fn covering_peers_must_serve_the_claimed_shards() {
        use crate::master_node::peer_info_file::test_prover;
        use quil_types::consensus::ProverStatus;
        let domain = [0xAB; 32];
        let root = domain.to_vec();
        let (joining, _) = registered(4, from_ref(&root), &[], "10.0.0.4");
        let joining_prover = test_prover(&[4; 897], &root, ProverStatus::Joining);
        let records = vec![
            registered(1, from_ref(&root), from_ref(&root), "10.0.0.1"),
            registered(2, from_ref(&root), &[[0xCD; 32].to_vec()], "10.0.0.2"),
            (joining, joining_prover),
        ];
        let mut cache: HashMap<_, _> = records
            .iter()
            .map(|(info, _)| (info.peer_id.clone(), info.clone()))
            .collect();
        // Unregistered, and sorting first.
        cache.insert(
            vec![9],
            peer(root.clone(), vec!["/ip4/10.0.0.0/tcp/8340".into()]),
        );
        let provers = records.into_iter().map(|(_, prover)| prover).collect();
        let reader = PeerCoinReader::new(
            Arc::new(parking_lot::RwLock::new(cache)),
            no_archives(),
            vec![0; 32],
            1,
        );
        assert!(reader.covering_endpoints(&domain).is_empty());
        let reader = reader.with_prover_registry(Arc::new(
            quil_engine::test_support::TestProverRegistry::with_provers(provers),
        ));
        assert_eq!(
            addrs(reader.covering_endpoints(&domain)),
            vec!["10.0.0.1:8340"]
        );
    }

    #[test]
    fn covering_partition_must_share_an_endpoint_and_peer() {
        let domain = [0xAB; 32];
        let shard = |path: &[bool]| quil_forest::encode_shard_bit_path(&domain, path);
        let complete = [
            shard(&[false, false]),
            shard(&[false, true]),
            shard(&[true]),
        ];
        let halves = [shard(&[false]), shard(&[true])];
        let mut separate_workers = registered(2, &halves, &halves, "10.0.0.2");
        separate_workers.0.reachability[1].stream_multiaddrs =
            vec!["/ip4/10.0.0.3/tcp/8340".into()];
        let long = quil_forest::encode_shard_bit_path(&domain, &vec![false; 65535]);
        let reader = reader_of(
            vec![
                registered(1, &complete, &complete, "10.0.0.1"),
                separate_workers,
                // Even if different peers advertise the same endpoint, neither
                // individually claims it can answer a complete scan.
                registered(3, &[shard(&[false])], &[shard(&[false])], "10.0.0.4"),
                registered(4, &[shard(&[true])], &[shard(&[true])], "10.0.0.4"),
                // Malformed suffixes must not count as a root advertisement.
                registered(
                    5,
                    &[[domain.to_vec(), vec![0x01, 0x02]].concat()],
                    &[[domain.to_vec(), vec![0x01, 0x02]].concat()],
                    "10.0.0.5",
                ),
                registered(6, from_ref(&long), from_ref(&long), "10.0.0.6"),
                // A complete partition claimed, two of its shards served.
                registered(7, &complete, &complete[..2], "10.0.0.7"),
            ],
            no_archives(),
        );
        assert_eq!(
            addrs(reader.covering_endpoints(&domain)),
            vec!["10.0.0.1:8340"]
        );
    }

    #[tokio::test]
    async fn covering_peer_failures_leave_a_separate_archive_budget() {
        let domain = [0xAB; 32];
        let root = domain.to_vec();
        let records: Vec<_> = (1..=4)
            .map(|i| registered(i, from_ref(&root), from_ref(&root), &format!("10.0.0.{i}")))
            .collect();
        let peer_of = |seed: u8| {
            let (info, _) = registered(seed, &[], &[], "");
            quil_p2p::PeerId::from_bytes(&info.peer_id).unwrap()
        };
        // The archive at the first covering endpoint is that prover: it is
        // asked once. The one at the second is pinned to no one, so a
        // record naming its address does not take its place.
        quil_rpc::archive_client::pin_archive_peer("10.0.0.1:8340", peer_of(1)).unwrap();
        let pool = no_archives();
        // A duplicate must not use an archive attempt, regardless of where
        // it appears in the pool. Distinct archives still get all three.
        for endpoint in [
            "10.0.0.1:8340",
            "10.0.1.1:8340",
            "10.0.0.2:8340",
            "10.0.1.2:8340",
            "10.0.1.3:8340",
            "10.0.1.4:8340",
        ] {
            pool.add(endpoint.into()).await;
        }
        let reader = reader_of(records, pool);
        let endpoints = reader.read_endpoints(&domain).await;
        assert_eq!(
            addrs(endpoints.clone()),
            vec![
                "10.0.0.1:8340",
                "10.0.0.2:8340",
                "10.0.0.3:8340",
                "10.0.1.1:8340",
                "10.0.0.2:8340",
                "10.0.1.2:8340",
            ]
        );
        assert_eq!(
            endpoints.iter().map(|e| e.peer).collect::<Vec<_>>(),
            vec![
                Some(peer_of(1)),
                Some(peer_of(2)),
                Some(peer_of(3)),
                None,
                None,
                None,
            ]
        );
        // Model three declining peers: an archive must still be attempted.
        let successful = endpoints.iter().find(|endpoint| endpoint.peer.is_none());
        assert_eq!(
            successful.map(|endpoint| endpoint.addr.as_str()),
            Some("10.0.1.1:8340")
        );
        assert_eq!(
            addrs(reader.read_endpoints(&[0xEE; 32]).await),
            vec!["10.0.0.1:8340", "10.0.1.1:8340", "10.0.0.2:8340"]
        );
    }

    /// A covering prover's endpoint is dialed only as that prover: a node
    /// there answering with another identity is refused before any read is
    /// sent, so a record cannot name another node's address and have that
    /// node answer for the prover. A connection kept for the prover is not
    /// handed to a read meant for another peer at that address.
    #[tokio::test]
    async fn a_covering_endpoint_is_dialed_only_as_its_prover() {
        use crate::master_node::peer_info_file::{another_peer, pqnoise_listener};
        let (addr, prover) = pqnoise_listener().await;
        let reader = PeerCoinReader::new(
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            no_archives(),
            quil_p2p::generate_falcon_signing_key(),
            1,
        );
        let impostor = ReadEndpoint {
            addr: addr.clone(),
            peer: Some(another_peer()),
        };
        let dials = AtomicU64::new(0);
        let endpoint = ReadEndpoint {
            addr,
            peer: Some(prover),
        };
        // The impostor is refused before the prover's connection is kept,
        // and again after it.
        for (expected, accepted) in [(&impostor, false), (&endpoint, true), (&impostor, false)] {
            let connected = tokio::time::timeout(
                Duration::from_secs(10),
                reader.connections.connect(expected, &dials),
            )
            .await
            .expect("the dial ends");
            match connected {
                Ok(_) if accepted => {}
                Ok(_) => panic!("a node answering as another peer stood in for the prover"),
                Err(error) if accepted => {
                    panic!("the prover was refused: {}", with_causes(&error))
                }
                Err(error) => {
                    let error = with_causes(&error);
                    assert!(error.contains("identity does not match"), "{error}");
                }
            }
        }
        assert!(reader
            .connections
            .open
            .lock()
            .by_endpoint
            .contains_key(&endpoint));
        assert_eq!(
            dials.load(Ordering::SeqCst),
            3,
            "the impostor was dialed again"
        );
    }

    #[tokio::test]
    async fn a_refused_witness_round_is_retried_within_its_budget() {
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let served = retry_within(Duration::from_millis(500), Duration::from_millis(5), || {
            let n = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move { (n >= 2).then_some(n) }
        })
        .await;
        assert_eq!(served, Some(2), "busy twice, then served");

        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let started = Instant::now();
        let refused: Option<()> =
            retry_within(Duration::from_millis(50), Duration::from_millis(10), || {
                attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async { None }
            })
            .await;
        assert!(refused.is_none());
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "the budget bounds the wait"
        );
        assert!((2..=6).contains(&attempts.load(std::sync::atomic::Ordering::SeqCst)));
    }

    // wallet-k4: two of five concurrent load transfers failed three seconds
    // in, "no node serving application answered this node", in the coin scan
    // before proving: covering nodes whose coin workers were busy refuse at
    // once, and only witnesses retried. Scans and marker reads keep asking
    // for the budget now; a continuation whose pinned peer is gone does not.
    #[tokio::test]
    async fn forwarded_scans_and_vertex_reads_retry_within_the_budget() {
        let reader = PeerCoinReader::new(
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            Arc::new(quil_rpc::ArchiveEndpointPool::new(Duration::ZERO)),
            vec![],
            1,
        )
        .with_read_retry(Duration::from_millis(60), Duration::from_millis(10));
        let domain = [3; 32];
        let started = Instant::now();
        assert!(reader.coin_page(domain, None, None, 0).await.is_err());
        assert!(reader.escrow_page(domain, None, None, 0).await.is_none());
        assert!(reader.vertex(domain, vec![4; 32]).await.is_none());
        assert!(
            started.elapsed() >= Duration::from_millis(150),
            "each read kept asking"
        );
        let started = Instant::now();
        assert!(reader
            .coin_page(domain, Some([5; 32]), Some([6; 32]), 0)
            .await
            .is_err());
        assert!(reader
            .escrow_page(domain, Some([5; 32]), None, 0)
            .await
            .is_none());
        assert!(
            started.elapsed() < Duration::from_millis(50),
            "a lost pin fails at once"
        );
    }

    /// When no peer answers a forwarded scan, the wallet's status says why
    /// (#698: the archives' "no root in snapshot" was lost behind a generic
    /// refusal): each distinct reason with its count, bounded.
    #[test]
    fn declines_are_counted_by_reason_and_bounded() {
        let mut declines = Declines::default();
        assert_eq!(declines.summary(), "no covering node or archive is known");
        declines.push("Unavailable: coin scan: no root in snapshot");
        assert_eq!(
            declines.summary(),
            "1 peer declined: 1x Unavailable: coin scan: no root in snapshot"
        );
        for _ in 0..2 {
            declines.push("Unavailable: coin scan: no root in snapshot");
        }
        declines.push("dial failed: transport error");
        assert_eq!(declines.summary(),
            "4 peers declined: 3x Unavailable: coin scan: no root in snapshot; 1x dial failed: transport error");
        declines.push(&"x".repeat(10_000));
        for i in 0..8 {
            declines.push(&format!("reason {i}"));
        }
        let summary = declines.summary();
        assert!(
            summary.starts_with("13 peers declined: 3x Unavailable"),
            "{summary}"
        );
        assert!(summary.ends_with("; and 7 other reasons"), "{summary}");
        assert!(
            summary.len() < 4 * (MAX_REASON_CHARS + 16) + 64,
            "{summary}"
        );
    }

    #[tokio::test]
    async fn a_forwarded_scan_nobody_answers_reports_each_peers_reason() {
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(Duration::ZERO));
        // Nothing listens on these ports.
        for endpoint in ["127.0.0.1:1", "127.0.0.1:2"] {
            pool.add(endpoint.into()).await;
        }
        let reader = PeerCoinReader::new(
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            pool,
            vec![0; 32],
            1,
        )
        .with_read_retry(Duration::ZERO, Duration::from_millis(1));
        let Err(reasons) = reader.coin_page([3; 32], None, None, 0).await else {
            panic!("nobody serves the application");
        };
        assert!(reasons.starts_with("2 peers declined: "), "{reasons}");
        assert!(reasons.contains("dial failed"), "{reasons}");
    }

    #[test]
    fn scan_pins_are_scoped_bounded_and_expire() {
        let reader = PeerCoinReader::new(
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            Arc::new(quil_rpc::ArchiveEndpointPool::new(Duration::ZERO)),
            vec![],
            1,
        );
        let domain = [1; 32];
        let id = [2; 32];
        reader.remember_scan(ScanKind::Coins, domain, id, "coins".into(), &page(true));
        reader.remember_scan(ScanKind::Escrows, domain, id, "escrows".into(), &page(true));
        assert_eq!(
            reader.pinned_endpoint(ScanKind::Coins, domain, id),
            Some(ReadEndpoint::from("coins"))
        );
        assert_eq!(
            reader.pinned_endpoint(ScanKind::Escrows, domain, id),
            Some(ReadEndpoint::from("escrows"))
        );
        assert!(reader
            .pinned_endpoint(ScanKind::Coins, [3; 32], id)
            .is_none());
        reader.remember_scan(ScanKind::Coins, domain, id, "coins".into(), &page(false));
        assert!(reader
            .pinned_endpoint(ScanKind::Coins, domain, id)
            .is_none());
        reader
            .served_by
            .lock()
            .get_mut(&(ScanKind::Escrows, domain, id))
            .unwrap()
            .used = Instant::now() - SCAN_PIN_TTL;
        assert!(reader
            .pinned_endpoint(ScanKind::Escrows, domain, id)
            .is_none());
        for i in 0..=MAX_PINNED_SCANS {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            reader.remember_scan(ScanKind::Coins, domain, id, "peer".into(), &page(true));
        }
        assert_eq!(reader.served_by.lock().len(), MAX_PINNED_SCANS);
        assert!(reader
            .pinned_endpoint(ScanKind::Coins, domain, [0; 32])
            .is_none());
    }

    /// A path to `target` that closes each connection once it has carried
    /// `limit` bytes of answers: what a peer or this node does when keepalive
    /// pings go unanswered behind a slow transfer, so the call fails with the
    /// real tonic error, not a stand-in.
    async fn cutting_path(target: String, limit: Arc<AtomicU64>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (client, _) = listener.accept().await.unwrap();
                let upstream = tokio::net::TcpStream::connect(&target).await.unwrap();
                let limit = limit.clone();
                tokio::spawn(async move {
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut upstream_read, mut upstream_write) = upstream.into_split();
                    let requests = tokio::spawn(async move {
                        let _ = tokio::io::copy(&mut client_read, &mut upstream_write).await;
                    });
                    let mut carried = 0;
                    let mut buffer = vec![0; 16 * 1024];
                    while let Ok(read) = upstream_read.read(&mut buffer).await {
                        carried += read as u64;
                        if read == 0
                            || carried > limit.load(Ordering::SeqCst)
                            || client_write.write_all(&buffer[..read]).await.is_err()
                        {
                            break;
                        }
                    }
                    requests.abort();
                });
            }
        });
        address
    }

    async fn plaintext_reader(endpoint: &str, budget: Duration) -> PeerCoinReader {
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(Duration::ZERO));
        pool.add(endpoint.to_string()).await;
        let dial: Dial<quil_rpc::ArchiveClient> = Arc::new(|endpoint: ReadEndpoint| {
            Box::pin(
                async move { quil_rpc::ArchiveClient::connect_plaintext(&endpoint.addr).await },
            )
        });
        PeerCoinReader::new(
            Arc::new(parking_lot::RwLock::new(HashMap::new())),
            pool,
            vec![0; 32],
            1,
        )
        .with_read_retry(budget, Duration::from_millis(5))
        .with_dial(dial)
    }

    /// Page through a scan from `snapshot`/`after`, returning the coin bytes.
    async fn read_scan(
        reader: &PeerCoinReader,
        mut snapshot: Option<[u8; 32]>,
        mut after: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, String> {
        let mut coins = Vec::new();
        loop {
            let page = reader.coin_page([3; 32], snapshot, after, 64).await?;
            coins.extend(page.coins.iter().map(|coin| coin.address[0]));
            if !page.has_more {
                return Ok(coins);
            }
            snapshot = Some(page.snapshot_id);
            after = page.cursor;
        }
    }

    /// neon, Nov 2: a 0.98 MB page over a 40 KB/s path was cut, and every
    /// attempt asked for the same size until a wallet's scan died on one h2
    /// body error, minutes in. A cut transfer now asks for less, for the rest
    /// of the scan, and the scan goes on from its cursor on the same peer.
    #[tokio::test]
    async fn a_page_cut_on_the_path_is_asked_again_smaller_and_the_scan_finishes() {
        let asked: Arc<parking_lot::Mutex<Vec<u32>>> = Arc::default();
        let (peer, _) = serve(Peer {
            pages: 96,
            memo_bytes: 4 * 1024,
            asked: asked.clone(),
            stall_above: u32::MAX,
        })
        .await;
        // 256 KiB for 64 coins does not fit a connection; 64 KiB for 16 does.
        let path = cutting_path(peer, Arc::new(AtomicU64::new(100 * 1024))).await;
        let reader = plaintext_reader(&path, Duration::from_secs(20)).await;
        let coins = read_scan(&reader, None, None).await.expect("the scan ends");
        assert_eq!(coins, (0..192).map(|i| i as u8).collect::<Vec<_>>());
        let asked = asked.lock().clone();
        assert_eq!(asked[..2], [64, 16], "a quarter after the cut: {asked:?}");
        // A connection that later dies between 16-coin pages fails at once as
        // a kept one and is replaced at the same size: no smaller page needed.
        assert!(
            asked[1..].iter().all(|size| *size <= 16),
            "a smaller page stays smaller for the scan: {asked:?}"
        );
        assert!(
            reader.served_by.lock().is_empty(),
            "the finished scan left no pin"
        );
    }

    /// The first bound: a peer that never finishes answering a large page is
    /// cut after the attempt's time, which the request deadline does not do
    /// once headers came, and a smaller page gets through.
    #[tokio::test]
    async fn a_stalled_page_attempt_is_cut_and_asked_again_smaller() {
        let asked: Arc<parking_lot::Mutex<Vec<u32>>> = Arc::default();
        let (peer, _) = serve(Peer {
            pages: 8,
            memo_bytes: 1024,
            asked: asked.clone(),
            stall_above: 8,
        })
        .await;
        let reader = plaintext_reader(&peer, Duration::from_secs(5))
            .await
            .with_page_attempt(Duration::from_millis(100));
        let scan = tokio::time::timeout(Duration::from_secs(20), read_scan(&reader, None, None));
        let coins = scan.await.expect("the attempts are bounded").unwrap();
        assert_eq!(coins, (0..16).map(|i| i as u8).collect::<Vec<_>>());
        assert_eq!(
            asked.lock()[..3],
            [64, 16, 8],
            "each step a quarter, then 8"
        );
    }

    /// The second bound: every attempt failing ends within the budget plus
    /// one attempt, which stays under the wallet's own call deadline.
    #[tokio::test]
    async fn a_page_nobody_delivers_ends_within_the_page_bound() {
        let (peer, _) = serve(Peer {
            pages: 8,
            memo_bytes: 1024,
            asked: Arc::default(),
            stall_above: 0,
        })
        .await;
        let reader = plaintext_reader(&peer, Duration::from_millis(250))
            .await
            .with_page_attempt(Duration::from_millis(100));
        let page = tokio::time::timeout(
            Duration::from_secs(5),
            reader.coin_page([3; 32], None, None, 64),
        );
        let Err(reasons) = page.await.expect("the attempts are bounded") else {
            panic!("the peer never answers");
        };
        assert!(reasons.contains("not delivered in"), "{reasons}");
    }

    /// The third bound and its recovery: a continuation whose every attempt
    /// is cut says which page it could not get and why, keeps the scan's pin,
    /// and the wallet asking again goes on from its cursor.
    #[tokio::test]
    async fn a_cut_continuation_names_its_attempts_and_cause_and_can_be_asked_again() {
        let asked: Arc<parking_lot::Mutex<Vec<u32>>> = Arc::default();
        let (peer, _) = serve(Peer {
            pages: 16,
            memo_bytes: 8 * 1024,
            asked: asked.clone(),
            stall_above: u32::MAX,
        })
        .await;
        let limit = Arc::new(AtomicU64::new(u64::MAX));
        let path = cutting_path(peer, limit.clone()).await;
        let reader = plaintext_reader(&path, Duration::from_millis(300)).await;
        let first = reader.coin_page([3; 32], None, None, 16).await.unwrap();
        // Room for an answer's headers and a part of its body: 8 coins' 64 KiB
        // is cut.
        limit.store(30 * 1024, Ordering::SeqCst);
        let (id, cursor) = (Some(first.snapshot_id), first.cursor);
        let Err(reasons) = reader.coin_page([3; 32], id, cursor, 8).await else {
            panic!("no attempt fits the path");
        };
        assert!(
            reasons.starts_with(
                "1 peer declined: 1x Unknown: h2 protocol error: error reading a body from connection"
            ),
            "{reasons}"
        );
        assert!(reasons.contains("pinned"), "{reasons}");
        assert!(reasons.contains("attempts"), "{reasons}");
        limit.store(u64::MAX, Ordering::SeqCst);
        asked.lock().clear();
        let rest = read_scan(&reader, id, cursor).await.expect("asked again");
        assert_eq!(rest, (16..32).map(|i| i as u8).collect::<Vec<_>>());
        assert_eq!(
            *asked.lock(),
            [8, 8],
            "the wallet's next asking keeps the size the path could carry"
        );
    }

    /// A reason keeps the causes under tonic's message, or a body error reads
    /// the same whatever ended the connection.
    #[test]
    fn a_status_reason_names_the_causes_under_it() {
        let mut status = Status::unknown("h2 protocol error: error reading a body");
        status.set_source(Arc::new(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "connection closed",
        )));
        assert_eq!(
            status_reason(&status),
            "Unknown: h2 protocol error: error reading a body: connection closed"
        );
        assert_eq!(
            status_reason(&Status::unavailable("busy")),
            "Unavailable: busy"
        );
    }

    #[test]
    fn a_page_shrinks_by_a_quarter_down_to_what_every_node_answers() {
        assert_eq!(smaller_page(64), 16);
        assert_eq!(smaller_page(16), 8);
        assert_eq!(smaller_page(8), 8);
        assert_eq!(smaller_page(2), 2, "never asks for more than it did");
    }

    /// A connection dying under a transfer is not a stale kept one: the same
    /// request again at once would only cost the same time again.
    #[tokio::test]
    async fn a_kept_connection_failing_late_is_not_called_again_at_once() {
        let mut connections = numbered_connections(Duration::from_secs(60), 2);
        connections.stale_failure = Duration::from_millis(20);
        let dials = AtomicU64::new(0);
        let number = |client: Arc<u64>| async move { Ok::<_, ArchiveClientError>(*client) };
        assert_eq!(
            connections.call(&"a".into(), &dials, number).await.ok(),
            Some(1)
        );
        let calls = AtomicU64::new(0);
        let late = connections
            .call(&"a".into(), &dials, |_: Arc<u64>| {
                calls.fetch_add(1, Ordering::SeqCst);
                async {
                    tokio::time::sleep(Duration::from_millis(40)).await;
                    Err::<u64, _>(closed())
                }
            })
            .await;
        assert!(matches!(late, Err(CallError::Call(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            connections.call(&"a".into(), &dials, number).await.ok(),
            Some(2),
            "the failed connection is gone"
        );
    }

    /// Unregistered records claiming an application, sorting before every
    /// archive, were the first three peers a wallet read asked.
    #[tokio::test]
    async fn reproduces_unregistered_covering_peers_asked_for_wallet_reads() {
        let domain = [0xAB; 32];
        let cache = (1..=3)
            .map(|i| {
                (
                    vec![i],
                    peer(domain.to_vec(), vec![format!("/ip4/10.0.0.{i}/tcp/8340")]),
                )
            })
            .collect();
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(
            std::time::Duration::ZERO,
        ));
        pool.add("10.0.1.1:8340".into()).await;
        let reader = PeerCoinReader::new(
            Arc::new(parking_lot::RwLock::new(cache)),
            pool,
            vec![0; 32],
            1,
        );
        let asked: Vec<String> = reader
            .read_endpoints(&domain)
            .await
            .iter()
            .map(|endpoint| endpoint.to_string())
            .collect();
        let unregistered: Vec<&String> = asked
            .iter()
            .filter(|endpoint| endpoint.starts_with("10.0.0."))
            .collect();
        assert!(
            unregistered.is_empty(),
            "unregistered peers asked for a wallet read: {unregistered:?} (in order {asked:?})"
        );
    }
}
