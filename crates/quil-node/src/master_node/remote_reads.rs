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
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
/// A peer's decline is logged at info at most this often per endpoint.
const DECLINE_LOG_INTERVAL: Duration = Duration::from_secs(60);
/// Distinct decline reasons named in a refusal, and each reason's length.
const MAX_REASONS: usize = 4;
const MAX_REASON_CHARS: usize = 200;

fn bounded_reason(reason: &str) -> String {
    reason.chars().take(MAX_REASON_CHARS).collect()
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

fn lost_pin() -> String {
    "the peer serving this scan is no longer pinned; restart the scan".into()
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
enum ScanKind {
    Coins,
    Escrows,
}

type ScanKey = (ScanKind, [u8; 32], [u8; 32]);

type PeerInfoCache = Arc<parking_lot::RwLock<HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>>>;

/// Reads an application's coins from whichever node holds it.
pub struct PeerCoinReader {
    peer_info_cache: PeerInfoCache,
    archive_pool: Arc<quil_rpc::ArchiveEndpointPool>,
    /// The `:8340` mTLS identity used for the outbound dial.
    falcon_key: Vec<u8>,
    network: u8,
    /// Scan snapshot → the endpoint that served it. A paged scan is pinned to
    /// one peer's snapshot, so continuing it anywhere else would restart the
    /// scan; the cursor means nothing to another node's store.
    served_by: parking_lot::Mutex<HashMap<ScanKey, (String, Instant)>>,
    /// `(budget, delay)` of each forwarded read's retries.
    read_retry: (Duration, Duration),
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
        Self {
            peer_info_cache,
            archive_pool,
            falcon_key,
            network,
            served_by: parking_lot::Mutex::new(HashMap::new()),
            read_retry: (READ_RETRY_BUDGET, READ_RETRY_DELAY),
            declines_logged: parking_lot::Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    fn with_read_retry(mut self, budget: Duration, delay: Duration) -> Self {
        self.read_retry = (budget, delay);
        self
    }

    /// Endpoints advertising a complete partition of `domain`. A child shard
    /// alone cannot answer an application-wide scan. Group by endpoint within
    /// each peer: cluster workers on different endpoints do not share stores.
    fn covering_endpoints(&self, domain: &[u8; 32]) -> Vec<String> {
        let cache = self.peer_info_cache.read();
        let mut endpoints = Vec::new();
        for info in cache.values() {
            let mut paths_by_endpoint: HashMap<String, Vec<Vec<bool>>> = HashMap::new();
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
                    paths_by_endpoint
                        .entry(endpoint)
                        .or_default()
                        .push(path.clone());
                }
            }
            endpoints.extend(
                paths_by_endpoint
                    .into_iter()
                    .filter_map(|(endpoint, paths)| {
                        super::grpc::shard_paths_cover_application(&paths).then_some(endpoint)
                    }),
            );
        }
        endpoints.sort();
        endpoints.dedup();
        endpoints
    }

    /// Bounded attempts in preference order, with room reserved for archives
    /// even when every advertised covering peer is stale or unreachable.
    async fn read_endpoints(&self, domain: &[u8; 32]) -> Vec<String> {
        let mut endpoints: Vec<_> = self
            .covering_endpoints(domain)
            .into_iter()
            .take(MAX_ATTEMPTS)
            .collect();
        let mut seen: HashSet<_> = endpoints.iter().cloned().collect();
        endpoints.extend(
            self.archive_pool
                .get_all()
                .await
                .into_iter()
                .filter(|endpoint| seen.insert(endpoint.clone()))
                .take(MAX_ATTEMPTS),
        );
        endpoints
    }

    fn pinned_endpoint(&self, kind: ScanKind, domain: [u8; 32], id: [u8; 32]) -> Option<String> {
        let mut pins = self.served_by.lock();
        pins.retain(|_, (_, used)| used.elapsed() < SCAN_PIN_TTL);
        let (endpoint, used) = pins.get_mut(&(kind, domain, id))?;
        *used = Instant::now();
        Some(endpoint.clone())
    }

    fn remember_scan(
        &self,
        kind: ScanKind,
        domain: [u8; 32],
        id: [u8; 32],
        endpoint: String,
        has_more: bool,
    ) {
        let mut pins = self.served_by.lock();
        pins.retain(|_, (_, used)| used.elapsed() < SCAN_PIN_TTL);
        if !has_more {
            pins.remove(&(kind, domain, id));
            return;
        }
        if pins.len() >= MAX_PINNED_SCANS && !pins.contains_key(&(kind, domain, id)) {
            if let Some(oldest) = pins
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(key, _)| *key)
            {
                pins.remove(&oldest);
            }
        }
        pins.insert((kind, domain, id), (endpoint, Instant::now()));
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
    /// "the application is empty".
    async fn page_from(
        &self,
        endpoint: &str,
        domain: &[u8; 32],
        snapshot_id: Option<&[u8; 32]>,
        after: Option<&[u8; 32]>,
        max_coins: u32,
    ) -> Result<CoinPageData, String> {
        let mut client = quil_rpc::ArchiveClient::connect_mtls(endpoint, &self.falcon_key)
            .await
            .map_err(|error| format!("dial failed: {}", with_causes(&error)))?;
        let page = client
            .list_shard_coins(
                domain.to_vec(),
                snapshot_id.map(|id| id.to_vec()).unwrap_or_default(),
                after.map(|a| a.to_vec()).unwrap_or_default(),
                max_coins,
            )
            .await
            .map_err(|error| match error {
                quil_rpc::ArchiveClientError::Rpc(status) => {
                    format!("{:?}: {}", status.code(), status.message())
                }
                other => with_causes(&other),
            })?;
        let malformed = || "malformed coin page".to_string();
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
        for endpoint in self.read_endpoints(&domain).await {
            let Ok(mut client) =
                quil_rpc::ArchiveClient::connect_mtls(&endpoint, &self.falcon_key).await
            else {
                continue;
            };
            let bundle = match client
                .get_shard_coin_witnesses(
                    domain.to_vec(),
                    addresses.iter().map(|a| a.to_vec()).collect(),
                )
                .await
            {
                Ok(bundle) => bundle,
                Err(error) => {
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
        for endpoint in self.read_endpoints(&domain).await {
            let Ok(mut client) =
                quil_rpc::ArchiveClient::connect_mtls(&endpoint, &self.falcon_key).await
            else {
                continue;
            };
            match client.get_shard_vertex(vertex_id.clone()).await {
                Ok(Some(blob)) => return Some((true, blob)),
                // The peer holds the application and has no such vertex: a real
                // answer (an unspent coin's marker is absent), not a miss.
                Ok(None) => return Some((false, Vec::new())),
                Err(error) => {
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
        let (budget, delay) = self.read_retry;
        retry_until_ok(budget, delay, || {
            self.coin_page_once(domain, snapshot_id, after, max_coins)
        })
        .await
    }

    async fn coin_page_once(
        &self,
        domain: [u8; 32],
        snapshot_id: Option<[u8; 32]>,
        after: Option<[u8; 32]>,
        max_coins: u32,
    ) -> Result<CoinPageData, String> {
        let endpoints = match snapshot_id {
            Some(id) => vec![self
                .pinned_endpoint(ScanKind::Coins, domain, id)
                .ok_or_else(lost_pin)?],
            None => self.read_endpoints(&domain).await,
        };
        let mut declines = Declines::default();
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
                )
                .await
            {
                Ok(page) if page.root_record.is_empty() => {
                    if rootless.is_none() {
                        rootless = Some(page);
                    }
                }
                Ok(page) => {
                    tracing::debug!(
                        %endpoint, application = %hex::encode(domain),
                        "served a coin page from a covering node or archive"
                    );
                    self.remember_scan(
                        ScanKind::Coins,
                        domain,
                        page.snapshot_id,
                        endpoint,
                        page.has_more,
                    );
                    return Ok(page);
                }
                Err(reason) => {
                    self.log_decline(&endpoint, &domain, &reason);
                    declines.push(&reason);
                }
            }
        }
        rootless.ok_or_else(|| declines.summary())
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
        let (budget, delay) = self.read_retry;
        retry_within(budget, delay, || {
            self.legacy_coins_once(domain, owner, after)
        })
        .await
    }

    async fn legacy_coins_once(
        &self,
        domain: [u8; 32],
        owner: [u8; 32],
        after: Option<[u8; 32]>,
    ) -> Option<quil_types::store::LegacyCoinPageData> {
        for endpoint in self
            .archive_pool
            .get_all()
            .await
            .into_iter()
            .take(MAX_ATTEMPTS)
        {
            let Ok(mut client) =
                quil_rpc::ArchiveClient::connect_mtls(&endpoint, &self.falcon_key).await
            else {
                continue;
            };
            let page = match client
                .list_shard_legacy_coins(
                    domain.to_vec(),
                    owner.to_vec(),
                    after.map(|a| a.to_vec()).unwrap_or_default(),
                )
                .await
            {
                Ok(page) => page,
                Err(error) => {
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
            if decoded.is_some() {
                return decoded;
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
        for endpoint in endpoints {
            let Ok(mut client) =
                quil_rpc::ArchiveClient::connect_mtls(&endpoint, &self.falcon_key).await
            else {
                continue;
            };
            let page = match client
                .list_shard_escrows(
                    domain.to_vec(),
                    snapshot_id.map(|id| id.to_vec()).unwrap_or_default(),
                    after.map(|id| id.to_vec()).unwrap_or_default(),
                    max_escrows,
                )
                .await
            {
                Ok(page) => page,
                Err(error) => {
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
                self.remember_scan(
                    ScanKind::Escrows,
                    domain,
                    page.snapshot_id,
                    endpoint,
                    page.has_more,
                );
                return Some(page);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// A partial holder or a peer covering a different application cannot
    /// answer an application-wide wallet read.
    #[test]
    fn covering_peers_are_selected_by_advertised_filter() {
        let domain = [0xAB; 32];
        let mut cache = HashMap::new();
        cache.insert(
            vec![1],
            peer(domain.to_vec(), vec!["/ip4/10.0.0.1/tcp/8340".into()]),
        );
        cache.insert(
            vec![2],
            peer([0xCD; 32].to_vec(), vec!["/ip4/10.0.0.2/tcp/8340".into()]),
        );
        cache.insert(
            vec![3],
            peer(
                quil_forest::encode_shard_bit_path(&domain, &[false]),
                vec!["/ip4/10.0.0.3/tcp/8340".into()],
            ),
        );
        let reader = PeerCoinReader::new(
            Arc::new(parking_lot::RwLock::new(cache)),
            Arc::new(quil_rpc::ArchiveEndpointPool::new(
                std::time::Duration::ZERO,
            )),
            vec![0; 32],
            1,
        );
        let endpoints = reader.covering_endpoints(&domain);
        assert_eq!(endpoints.len(), 1, "{endpoints:?}");
        assert!(endpoints[0].contains("10.0.0.1"), "{endpoints:?}");
        // An application nobody advertises has no covering candidate; the
        // caller then falls back to archives, and failing those, refuses.
        assert!(reader.covering_endpoints(&[0xEE; 32]).is_empty());
    }

    #[test]
    fn covering_partition_must_share_an_endpoint_and_peer() {
        let domain = [0xAB; 32];
        let reach = |path: &[bool], host: &str| {
            peer(
                quil_forest::encode_shard_bit_path(&domain, path),
                vec![format!("/ip4/{host}/tcp/8340")],
            )
            .reachability
            .remove(0)
        };
        let mut complete = quil_p2p::CanonicalPeerInfo::default();
        complete.reachability = vec![
            reach(&[false, false], "10.0.0.1"),
            reach(&[false, true], "10.0.0.1"),
            reach(&[true], "10.0.0.1"),
        ];
        let mut separate_workers = quil_p2p::CanonicalPeerInfo::default();
        separate_workers.reachability =
            vec![reach(&[false], "10.0.0.2"), reach(&[true], "10.0.0.3")];
        let cache = HashMap::from([
            (vec![1], complete),
            (vec![2], separate_workers),
            // Even if different peers advertise the same endpoint, neither
            // individually claims it can answer a complete scan.
            (
                vec![3],
                peer(
                    quil_forest::encode_shard_bit_path(&domain, &[false]),
                    vec!["/ip4/10.0.0.4/tcp/8340".into()],
                ),
            ),
            (
                vec![4],
                peer(
                    quil_forest::encode_shard_bit_path(&domain, &[true]),
                    vec!["/ip4/10.0.0.4/tcp/8340".into()],
                ),
            ),
            // Malformed suffixes must not count as a root advertisement.
            (
                vec![5],
                peer(
                    [domain.to_vec(), vec![0x01, 0x02]].concat(),
                    vec!["/ip4/10.0.0.5/tcp/8340".into()],
                ),
            ),
            (
                vec![6],
                peer(
                    quil_forest::encode_shard_bit_path(&domain, &vec![false; 65535]),
                    vec!["/ip4/10.0.0.6/tcp/8340".into()],
                ),
            ),
        ]);
        let reader = PeerCoinReader::new(
            Arc::new(parking_lot::RwLock::new(cache)),
            Arc::new(quil_rpc::ArchiveEndpointPool::new(
                std::time::Duration::ZERO,
            )),
            vec![0; 32],
            1,
        );
        assert_eq!(reader.covering_endpoints(&domain), vec!["10.0.0.1:8340"]);
    }

    #[tokio::test]
    async fn covering_peer_failures_leave_a_separate_archive_budget() {
        let domain = [0xAB; 32];
        let cache = (1..=4)
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
        let reader = PeerCoinReader::new(
            Arc::new(parking_lot::RwLock::new(cache)),
            pool,
            vec![0; 32],
            1,
        );
        let endpoints = reader.read_endpoints(&domain).await;
        assert_eq!(
            endpoints,
            vec![
                "10.0.0.1:8340",
                "10.0.0.2:8340",
                "10.0.0.3:8340",
                "10.0.1.1:8340",
                "10.0.1.2:8340",
                "10.0.1.3:8340",
            ]
        );
        // Model three declining peers: an archive must still be attempted.
        let successful = endpoints
            .iter()
            .find(|endpoint| endpoint.starts_with("10.0.1."));
        assert_eq!(successful.map(String::as_str), Some("10.0.1.1:8340"));
        assert_eq!(
            reader.read_endpoints(&[0xEE; 32]).await,
            vec!["10.0.0.1:8340", "10.0.1.1:8340", "10.0.0.2:8340"]
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
        reader.remember_scan(ScanKind::Coins, domain, id, "coins".into(), true);
        reader.remember_scan(ScanKind::Escrows, domain, id, "escrows".into(), true);
        assert_eq!(
            reader
                .pinned_endpoint(ScanKind::Coins, domain, id)
                .as_deref(),
            Some("coins")
        );
        assert_eq!(
            reader
                .pinned_endpoint(ScanKind::Escrows, domain, id)
                .as_deref(),
            Some("escrows")
        );
        assert!(reader
            .pinned_endpoint(ScanKind::Coins, [3; 32], id)
            .is_none());
        reader.remember_scan(ScanKind::Coins, domain, id, "coins".into(), false);
        assert!(reader
            .pinned_endpoint(ScanKind::Coins, domain, id)
            .is_none());
        reader
            .served_by
            .lock()
            .get_mut(&(ScanKind::Escrows, domain, id))
            .unwrap()
            .1 = Instant::now() - SCAN_PIN_TTL;
        assert!(reader
            .pinned_endpoint(ScanKind::Escrows, domain, id)
            .is_none());
        for i in 0..=MAX_PINNED_SCANS {
            let mut id = [0; 32];
            id[..8].copy_from_slice(&(i as u64).to_be_bytes());
            reader.remember_scan(ScanKind::Coins, domain, id, "peer".into(), true);
        }
        assert_eq!(reader.served_by.lock().len(), MAX_PINNED_SCANS);
        assert!(reader
            .pinned_endpoint(ScanKind::Coins, domain, [0; 32])
            .is_none());
    }
}
