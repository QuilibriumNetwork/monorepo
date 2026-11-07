//! `RemoteTreeReader` — a [`jmt::storage::TreeReader`] backed by a peer's
//! `GetForestNode`/`GetForestValue` gRPC, so [`quil_forest::diff_leaves`] can
//! walk a remote shard/phase tree and pull only the nodes whose hash differs
//! from the local one.
//!
//! # Sync-over-async
//!
//! jmt's `TreeReader` is synchronous; the gRPC client is async. Each read
//! blocks the calling thread on the gRPC via a [`tokio::runtime::Handle`], so
//! `RemoteTreeReader` MUST be used from a blocking context (run the diff inside
//! `tokio::task::spawn_blocking`) — never on a runtime worker thread, where
//! `block_on` would panic.

use std::future::Future;
use std::time::Duration;

use anyhow::Result;
use futures::stream::{self, StreamExt, TryStreamExt};
use jmt::storage::{LeafNode, Node, NodeKey, TreeReader};
use jmt::{KeyHash, OwnedValue, Version};

use crate::archive_client::{ArchiveClient, ArchiveClientError};

/// Keys per batched request (the archive takes up to 512).
pub const REMOTE_BATCH_KEYS: usize = 256;
/// Batched requests in flight at once: the archive lets one peer hold four
/// of its storage read slots.
pub const REMOTE_BATCHES_IN_FLIGHT: usize = 4;
/// How long a request keeps retrying an archive that answers busy before
/// the walk gives up on that archive.
const BUSY_RETRY_FOR: Duration = Duration::from_secs(90);
/// Times a request is sent again after outrunning its deadline. One slow
/// answer used to end a whole download attempt, however far it had come.
const TIMEOUT_RETRIES: usize = 3;

/// Run `request` until it succeeds, retrying an archive that answers busy
/// or too slowly (with backoff) and a connection that dropped (at once, a
/// few times).
pub async fn retry_forest_read<T, F, Fut>(request: F) -> std::result::Result<T, ArchiveClientError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<T, ArchiveClientError>>,
{
    retry_forest_read_within(BUSY_RETRY_FOR, TIMEOUT_RETRIES, request).await
}

/// [`ArchiveClient::get_forest_head`], retrying while the archive is busy.
pub async fn forest_head(
    client: &ArchiveClient,
    shard_id: Vec<u8>,
    phase: u32,
) -> std::result::Result<Option<(u64, Vec<u8>)>, ArchiveClientError> {
    retry_forest_read(|| {
        let (mut client, shard_id) = (client.clone(), shard_id.clone());
        async move { client.get_forest_head(shard_id, phase).await }
    })
    .await
}

/// [`ArchiveClient::resolve_root`], retrying while the archive is busy.
pub async fn resolve_forest_root(
    client: &ArchiveClient,
    shard_id: Vec<u8>,
    phase: u32,
    root: Vec<u8>,
) -> std::result::Result<Option<(u64, u64)>, ArchiveClientError> {
    retry_forest_read(|| {
        let (mut client, shard_id, root) = (client.clone(), shard_id.clone(), root.clone());
        async move { client.resolve_root(shard_id, phase, root).await }
    })
    .await
}

async fn retry_forest_read_within<T, F, Fut>(
    busy_for: Duration,
    timeout_retries: usize,
    mut request: F,
) -> std::result::Result<T, ArchiveClientError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<T, ArchiveClientError>>,
{
    let started = std::time::Instant::now();
    let mut backoff = Duration::from_millis(200);
    let mut transport_retries = 0;
    let mut timeouts = 0;
    loop {
        match request().await {
            Err(e) if e.is_busy() && started.elapsed() < busy_for => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
            }
            Err(e) if e.is_timeout() && timeouts < timeout_retries => {
                timeouts += 1;
                tracing::debug!(timeouts, error = %e, "archive read outran its deadline; sending it again");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(5));
            }
            Err(e) if e.is_transport_failure() && transport_retries < 3 => {
                transport_retries += 1;
            }
            other => return other,
        }
    }
}

/// Fetch `keys` with `fetch` in batches of `REMOTE_BATCH_KEYS`, several in
/// flight, each batch re-requested from where a partial answer stopped.
///
/// A request that outruns its deadline is sent again with half as many keys,
/// down to one, and the batches of this fetch keep the smaller size: a link
/// too slow for a full batch's answer (up to the archive's byte cap) within
/// the client deadline otherwise fails every attempt the same way. Only a
/// single-key request is sent again at the same size.
pub async fn fetch_in_batches<K, V, F, Fut>(
    keys: Vec<K>,
    fetch: F,
) -> std::result::Result<Vec<V>, ArchiveClientError>
where
    K: Clone + Send,
    F: Fn(Vec<K>) -> Fut + Clone,
    Fut: Future<Output = std::result::Result<Vec<V>, ArchiveClientError>>,
{
    let chunks: Vec<Vec<K>> = keys.chunks(REMOTE_BATCH_KEYS).map(<[K]>::to_vec).collect();
    let batch_keys = std::sync::atomic::AtomicUsize::new(REMOTE_BATCH_KEYS);
    let batch_keys = &batch_keys;
    let answers: Vec<Vec<V>> = stream::iter(chunks)
        .map(|chunk| {
            let fetch = fetch.clone();
            async move {
                let mut answered = Vec::with_capacity(chunk.len());
                while answered.len() < chunk.len() {
                    let rest = &chunk[answered.len()..];
                    let size = batch_keys.load(std::sync::atomic::Ordering::Relaxed).min(rest.len());
                    let ask = rest[..size].to_vec();
                    let retries = if size == 1 { TIMEOUT_RETRIES } else { 0 };
                    let part = match retry_forest_read_within(BUSY_RETRY_FOR, retries, || fetch(ask.clone())).await {
                        Err(e) if e.is_timeout() && size > 1 => {
                            batch_keys.fetch_min(size / 2, std::sync::atomic::Ordering::Relaxed);
                            tracing::debug!(keys = size / 2, error = %e, "batched archive read outran its deadline; asking for fewer keys");
                            continue;
                        }
                        other => other?,
                    };
                    if part.is_empty() || part.len() > ask.len() {
                        return Err(ArchiveClientError::MissingField("batched forest read answered nothing"));
                    }
                    answered.extend(part);
                }
                Ok(answered)
            }
        })
        .buffered(REMOTE_BATCHES_IN_FLIGHT)
        .try_collect()
        .await?;
    Ok(answers.into_iter().flatten().collect())
}

/// Bounds of one leaf listing ([`quil_forest::BatchTreeReader::leaves_under`]).
/// A listing is checked against its subtree's root only once complete, so an
/// archive could otherwise keep listing into memory without end. Past a
/// bound the subtree is walked node by node instead, each node checked as it
/// arrives, and its large children are listed in turn: an honest subtree
/// past a bound costs at most the bound downloaded twice, not a stalled
/// sync.
#[derive(Clone, Copy, Debug)]
struct ListingBounds {
    leaves: usize,
    /// Keys and values.
    bytes: usize,
    deadline: Duration,
}

const LISTING_BOUNDS: ListingBounds = ListingBounds {
    leaves: 1 << 22,
    bytes: 1 << 30,
    deadline: Duration::from_secs(30 * 60),
};

/// A page of a leaf listing, and whether more leaves follow it.
type LeafPage = (Vec<([u8; 32], Vec<u8>)>, bool);

/// What [`list_leaves`] got.
enum Listing {
    Complete(Vec<(KeyHash, OwnedValue)>),
    /// Stopped past its [`ListingBounds`], holding this many leaves and bytes.
    Bounded {
        leaves: usize,
        bytes: usize,
    },
}

/// Every leaf in `[first, last]`, page by page from `fetch(after)`, each
/// page's size reported to `on_page`. Each page must continue past the last
/// in strictly ascending key order within the range: a listing that does
/// not advance, or leaves its range, would never end. Its content is
/// checked by the caller.
async fn list_leaves<F, Fut>(
    bounds: ListingBounds,
    first: [u8; 32],
    last: [u8; 32],
    mut fetch: F,
    mut on_page: impl FnMut(usize),
) -> std::result::Result<Listing, ArchiveClientError>
where
    F: FnMut(Option<[u8; 32]>) -> Fut,
    Fut: Future<Output = std::result::Result<LeafPage, ArchiveClientError>>,
{
    let started = std::time::Instant::now();
    let mut leaves: Vec<(KeyHash, OwnedValue)> = Vec::new();
    let mut bytes = 0usize;
    let mut after: Option<[u8; 32]> = None;
    loop {
        let (page, more) = fetch(after).await?;
        let mut previous = after;
        let in_order = page.iter().all(|(key, _)| {
            let in_range = first <= *key && *key <= last;
            let advances = previous.is_none_or(|before| before < *key);
            previous = Some(*key);
            in_range && advances
        });
        if !in_order || (more && page.is_empty()) {
            return Err(ArchiveClientError::MissingField(
                "forest leaf listing did not advance in key order within its range",
            ));
        }
        on_page(page.len());
        after = previous;
        bytes = page.iter().fold(bytes, |total, (_, value)| {
            total.saturating_add(32 + value.len())
        });
        leaves.extend(page.into_iter().map(|(key, value)| (KeyHash(key), value)));
        if !more {
            return Ok(Listing::Complete(leaves));
        }
        if leaves.len() > bounds.leaves
            || bytes > bounds.bytes
            || started.elapsed() >= bounds.deadline
        {
            return Ok(Listing::Bounded {
                leaves: leaves.len(),
                bytes,
            });
        }
    }
}

/// A walk logs its progress only once it is long: past this many reads or
/// [`WALK_LOG_AFTER`]. The GLOBAL prover tree's routine walks (about 10k
/// reads in seconds) stay quiet.
const WALK_LOG_READS: u64 = 1 << 16;
const WALK_LOG_AFTER: Duration = Duration::from_secs(30);

/// A remote view of ONE shard/phase tree on a peer archive, addressed by
/// `(shard_id, phase)`. Clone-cheap (the client shares one h2 channel).
pub struct RemoteTreeReader {
    client: ArchiveClient,
    handle: tokio::runtime::Handle,
    shard_id: Vec<u8>,
    /// What progress lines name: the tree id, or the full shard filter
    /// whose subtree this reader walks ([`Self::labelled`]).
    label: Vec<u8>,
    phase: u32,
    /// Remote reads so far and when the walk started, for progress lines.
    reads: std::sync::atomic::AtomicU64,
    started: std::time::Instant,
    /// Cleared when the archive lacks the batched calls (an older build):
    /// reads then go one key per request, still several in flight.
    batched: std::sync::atomic::AtomicBool,
    /// Cleared when the archive cannot list leaves (an older build): an empty
    /// subtree is then walked node by node.
    listing: std::sync::atomic::AtomicBool,
}

impl RemoteTreeReader {
    /// `handle` is the runtime to drive gRPC on; the reader must be *called*
    /// from a blocking thread (`spawn_blocking`), not a worker of `handle`.
    pub fn new(
        client: ArchiveClient,
        handle: tokio::runtime::Handle,
        shard_id: Vec<u8>,
        phase: u32,
    ) -> Self {
        Self {
            client,
            handle,
            label: shard_id.clone(),
            shard_id,
            phase,
            reads: std::sync::atomic::AtomicU64::new(0),
            started: std::time::Instant::now(),
            batched: std::sync::atomic::AtomicBool::new(true),
            listing: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Name a full shard filter in progress lines instead of the tree id.
    pub fn labelled(mut self, label: Vec<u8>) -> Self {
        self.label = label;
        self
    }

    /// Count remote reads (nodes or values). Log each time the count passes a
    /// power of two from 1,024 once the walk is long ([`WALK_LOG_READS`]), so
    /// a long walk shows progress in a few lines and a routine one none.
    fn counted(&self, n: usize) {
        let before = self
            .reads
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        let reads = before + n as u64;
        let crossed =
            reads >= 1024 && (64 - before.leading_zeros()) != (64 - reads.leading_zeros());
        if (crossed || (reads >= 1024 && reads.is_power_of_two()))
            && (reads >= WALK_LOG_READS || self.started.elapsed() >= WALK_LOG_AFTER)
        {
            tracing::info!(
                shard = %hex::encode(&self.label),
                phase = self.phase,
                reads,
                elapsed_secs = self.started.elapsed().as_secs(),
                "remote tree walk in progress",
            );
        }
    }
}

impl TreeReader for RemoteTreeReader {
    fn get_node_option(&self, node_key: &NodeKey) -> Result<Option<Node>> {
        self.counted(1);
        let key_bytes = borsh::to_vec(node_key)?;
        let mut client = self.client.clone();
        let shard_id = self.shard_id.clone();
        let phase = self.phase;
        let bytes = self
            .handle
            .block_on(async move { client.get_forest_node(shard_id, phase, key_bytes).await })
            .map_err(|e| anyhow::anyhow!("remote get_forest_node: {e}"))?;
        match bytes {
            Some(b) => Ok(Some(borsh::from_slice(&b)?)),
            None => Ok(None),
        }
    }

    fn get_value_option(
        &self,
        max_version: Version,
        key_hash: KeyHash,
    ) -> Result<Option<OwnedValue>> {
        self.counted(1);
        let mut client = self.client.clone();
        let shard_id = self.shard_id.clone();
        let phase = self.phase;
        let kh = key_hash.0.to_vec();
        self.handle
            .block_on(async move {
                client
                    .get_forest_value(shard_id, phase, max_version, kh)
                    .await
            })
            .map_err(|e| anyhow::anyhow!("remote get_forest_value: {e}"))
    }

    fn get_rightmost_leaf(&self) -> Result<Option<(NodeKey, LeafNode)>> {
        // Used only by jmt's restore path, which the Merkle-diff sync never
        // exercises — the diff walk addresses nodes explicitly.
        Ok(None)
    }
}

impl RemoteTreeReader {
    fn note_unbatched(&self, error: &ArchiveClientError) -> bool {
        if error.is_unimplemented()
            && self
                .batched
                .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            tracing::info!(
                "archive lacks batched forest reads (older build); reading one key per request"
            );
            return true;
        }
        error.is_unimplemented()
    }

    async fn nodes(
        &self,
        keys: Vec<Vec<u8>>,
    ) -> std::result::Result<Vec<Option<Vec<u8>>>, ArchiveClientError> {
        let (client, shard_id, phase) = (self.client.clone(), self.shard_id.clone(), self.phase);
        if self.batched.load(std::sync::atomic::Ordering::Relaxed) {
            let fetched = fetch_in_batches(keys.clone(), |chunk: Vec<Vec<u8>>| {
                let (mut client, shard_id) = (client.clone(), shard_id.clone());
                async move { client.get_forest_nodes(shard_id, phase, chunk).await }
            })
            .await;
            match fetched {
                Err(e) if self.note_unbatched(&e) => {}
                other => return other,
            }
        }
        stream::iter(keys)
            .map(|key| {
                let (client, shard_id) = (client.clone(), shard_id.clone());
                async move {
                    retry_forest_read(|| {
                        let (mut client, shard_id, key) =
                            (client.clone(), shard_id.clone(), key.clone());
                        async move { client.get_forest_node(shard_id, phase, key).await }
                    })
                    .await
                }
            })
            .buffered(REMOTE_BATCHES_IN_FLIGHT)
            .try_collect()
            .await
    }

    /// Every leaf in `[first, last]` at `version`, page by page; `None` once
    /// the listing passes its [`ListingBounds`].
    async fn listed(
        &self,
        version: u64,
        first: [u8; 32],
        last: [u8; 32],
    ) -> std::result::Result<Option<Vec<(KeyHash, OwnedValue)>>, ArchiveClientError> {
        let started = std::time::Instant::now();
        let fetch = |after: Option<[u8; 32]>| {
            retry_forest_read(move || {
                let (mut client, shard_id) = (self.client.clone(), self.shard_id.clone());
                async move {
                    client
                        .get_forest_leaves(shard_id, self.phase, version, first, last, after)
                        .await
                }
            })
        };
        let on_page = |count| self.counted(count);
        let listed = list_leaves(LISTING_BOUNDS, first, last, fetch, on_page).await?;
        match listed {
            Listing::Complete(leaves) => Ok(Some(leaves)),
            Listing::Bounded { leaves, bytes } => {
                tracing::info!(
                    shard = %hex::encode(&self.label),
                    phase = self.phase,
                    leaves,
                    bytes,
                    elapsed_secs = started.elapsed().as_secs(),
                    "forest leaf listing passed its bounds (a very large subtree, or an archive \
                     listing without end); walking the subtree node by node instead",
                );
                Ok(None)
            }
        }
    }

    async fn values(
        &self,
        reads: Vec<(u64, Vec<u8>)>,
    ) -> std::result::Result<Vec<Option<Vec<u8>>>, ArchiveClientError> {
        let (client, shard_id, phase) = (self.client.clone(), self.shard_id.clone(), self.phase);
        if self.batched.load(std::sync::atomic::Ordering::Relaxed) {
            let fetched = fetch_in_batches(reads.clone(), |chunk: Vec<(u64, Vec<u8>)>| {
                let (mut client, shard_id) = (client.clone(), shard_id.clone());
                async move { client.get_forest_values(shard_id, phase, chunk).await }
            })
            .await;
            match fetched {
                Err(e) if self.note_unbatched(&e) => {}
                other => return other,
            }
        }
        stream::iter(reads)
            .map(|(version, key)| {
                let (client, shard_id) = (client.clone(), shard_id.clone());
                async move {
                    retry_forest_read(|| {
                        let (mut client, shard_id, key) =
                            (client.clone(), shard_id.clone(), key.clone());
                        async move { client.get_forest_value(shard_id, phase, version, key).await }
                    })
                    .await
                }
            })
            .buffered(REMOTE_BATCHES_IN_FLIGHT)
            .try_collect()
            .await
    }
}

impl quil_forest::BatchTreeReader for RemoteTreeReader {
    fn get_nodes(&self, keys: &[NodeKey]) -> Result<Vec<Option<Node>>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        self.counted(keys.len());
        let encoded = keys
            .iter()
            .map(borsh::to_vec)
            .collect::<std::io::Result<Vec<_>>>()?;
        let answers = self
            .handle
            .block_on(self.nodes(encoded))
            .map_err(|e| anyhow::anyhow!("remote get_forest_nodes: {e}"))?;
        answers
            .into_iter()
            .map(|bytes| {
                bytes
                    .map(|b| borsh::from_slice(&b))
                    .transpose()
                    .map_err(Into::into)
            })
            .collect()
    }

    fn leaves_under(
        &self,
        version: Version,
        bit_path: &[bool],
    ) -> Result<Option<Vec<(KeyHash, OwnedValue)>>> {
        if !self.listing.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(None);
        }
        let (first, last) = quil_forest::key_range_under(bit_path);
        match self.handle.block_on(self.listed(version, first, last)) {
            Ok(leaves) => Ok(leaves),
            Err(e) if e.is_unimplemented() => {
                self.listing
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                tracing::info!("archive cannot list forest leaves (older build); walking the tree");
                Ok(None)
            }
            Err(e) => Err(anyhow::anyhow!("remote get_forest_leaves: {e}")),
        }
    }

    fn get_values(&self, reads: &[(Version, KeyHash)]) -> Result<Vec<Option<OwnedValue>>> {
        if reads.is_empty() {
            return Ok(Vec::new());
        }
        self.counted(reads.len());
        let reads = reads
            .iter()
            .map(|(version, key)| (*version, key.0.to_vec()))
            .collect();
        self.handle
            .block_on(self.values(reads))
            .map_err(|e| anyhow::anyhow!("remote get_forest_values: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn busy() -> ArchiveClientError {
        ArchiveClientError::Rpc(tonic::Status::resource_exhausted(
            "forest read workers busy; retry later",
        ))
    }

    /// A read that outruns its deadline goes again a bounded number of
    /// times; an archive that keeps outrunning it fails the request.
    #[tokio::test]
    async fn timed_out_reads_are_sent_again_a_few_times() {
        let timeout = || ArchiveClientError::Rpc(tonic::Status::cancelled("Timeout expired"));
        assert!(
            timeout().is_timeout() && !timeout().is_busy() && !timeout().is_transport_failure()
        );
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let answered = retry_forest_read(|| {
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move {
                if n < 2 {
                    Err(timeout())
                } else {
                    Ok(n)
                }
            }
        })
        .await;
        assert_eq!(answered.unwrap(), 2);
        calls.store(0, std::sync::atomic::Ordering::SeqCst);
        let failed: std::result::Result<(), _> = retry_forest_read(|| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Err(timeout()) }
        })
        .await;
        assert!(failed.unwrap_err().is_timeout());
        assert_eq!(
            calls.load(std::sync::atomic::Ordering::SeqCst),
            1 + TIMEOUT_RETRIES
        );
    }

    /// Partial answers are completed from where they stopped, batches come
    /// back in request order, and a busy archive is retried.
    #[tokio::test]
    async fn batches_complete_partial_answers_in_order_and_retry_busy() {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let keys: Vec<u32> = (0..(REMOTE_BATCH_KEYS as u32 * 3 + 7)).collect();
        let fetch = {
            let calls = calls.clone();
            move |chunk: Vec<u32>| {
                let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async move {
                    if n == 0 {
                        return Err(busy());
                    }
                    // Answer at most 100 keys per request.
                    Ok(chunk
                        .into_iter()
                        .take(100)
                        .map(|k| k * 2)
                        .collect::<Vec<_>>())
                }
            }
        };
        let answers = fetch_in_batches(keys.clone(), fetch).await.unwrap();
        assert_eq!(answers, keys.iter().map(|k| k * 2).collect::<Vec<_>>());
        assert!(calls.load(std::sync::atomic::Ordering::SeqCst) > 8);

        let empty = fetch_in_batches(vec![1u32], |_chunk: Vec<u32>| async {
            Ok(Vec::<u32>::new())
        })
        .await;
        assert!(
            empty.is_err(),
            "an archive that answers nothing does not loop"
        );
        let refused = fetch_in_batches(vec![1u32], |_chunk: Vec<u32>| async {
            Err::<Vec<u32>, _>(ArchiveClientError::Rpc(tonic::Status::unimplemented(
                "old archive",
            )))
        })
        .await;
        assert!(refused.unwrap_err().is_unimplemented());
    }

    /// A link too slow for a full batch within the deadline still completes:
    /// requests shrink after a timeout, later batches keep the smaller size,
    /// and answers come back in request order.
    #[tokio::test]
    async fn timed_out_batches_are_asked_again_with_fewer_keys() {
        let timeout = || ArchiveClientError::Rpc(tonic::Status::cancelled("Timeout expired"));
        let largest = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let timeouts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let keys: Vec<u32> = (0..(REMOTE_BATCH_KEYS as u32 * 6 + 5)).collect();
        let fetch = {
            let (largest, timeouts) = (largest.clone(), timeouts.clone());
            move |chunk: Vec<u32>| {
                let (largest, timeouts) = (largest.clone(), timeouts.clone());
                async move {
                    // The link answers at most 40 keys within the deadline.
                    if chunk.len() > 40 {
                        timeouts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        return Err(timeout());
                    }
                    largest.fetch_max(chunk.len(), std::sync::atomic::Ordering::SeqCst);
                    Ok(chunk.into_iter().map(|k| k * 2).collect::<Vec<_>>())
                }
            }
        };
        let answers = fetch_in_batches(keys.clone(), fetch).await.unwrap();
        assert_eq!(answers, keys.iter().map(|k| k * 2).collect::<Vec<_>>());
        assert_eq!(
            largest.load(std::sync::atomic::Ordering::SeqCst),
            REMOTE_BATCH_KEYS / 8
        );
        // 256 → 128 → 64 → 32: three halvings, a few more from the batches
        // already in flight, not one per batch.
        assert!(timeouts.load(std::sync::atomic::Ordering::SeqCst) <= 3 * REMOTE_BATCHES_IN_FLIGHT);

        let stuck: std::result::Result<Vec<u32>, _> =
            fetch_in_batches(vec![1u32, 2], move |_chunk: Vec<u32>| async move {
                Err::<Vec<u32>, _>(timeout())
            })
            .await;
        assert!(
            stuck.unwrap_err().is_timeout(),
            "a link that answers not even one key gives up"
        );
    }

    fn key(n: u64) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[24..].copy_from_slice(&n.to_be_bytes());
        key
    }

    type PageFuture = futures::future::Ready<std::result::Result<LeafPage, ArchiveClientError>>;

    /// A listing answering `pages` in turn, the last without more to follow.
    fn pages(pages: Vec<Vec<u64>>) -> impl FnMut(Option<[u8; 32]>) -> PageFuture {
        let mut pages = pages.into_iter();
        move |_after: Option<[u8; 32]>| {
            let page = pages.next().unwrap_or_default();
            let more = !pages.as_slice().is_empty();
            let leaves: Vec<([u8; 32], Vec<u8>)> =
                page.into_iter().map(|n| (key(n), vec![1; 100])).collect();
            futures::future::ready(Ok((leaves, more)))
        }
    }

    /// A listing that keeps listing past the last key asked for.
    fn endless(per_page: u64) -> impl FnMut(Option<[u8; 32]>) -> PageFuture {
        move |after: Option<[u8; 32]>| {
            let next = after.map_or(0, |after| {
                u64::from_be_bytes(after[24..].try_into().unwrap()) + 1
            });
            let leaves: Vec<([u8; 32], Vec<u8>)> = (next..next + per_page)
                .map(|n| (key(n), vec![1; 100]))
                .collect();
            futures::future::ready(Ok((leaves, true)))
        }
    }

    /// Pages must ascend strictly, past the last page, within the range
    /// asked for; an empty page must end the listing.
    #[tokio::test]
    async fn listing_pages_must_ascend_within_their_range() {
        let (first, last) = (key(10), key(100));
        let listed = list_leaves(
            LISTING_BOUNDS,
            first,
            last,
            pages(vec![vec![10, 11], vec![12, 100], vec![]]),
            |_| {},
        )
        .await
        .unwrap();
        assert!(matches!(listed, Listing::Complete(leaves) if leaves.len() == 4));
        for refused in [
            vec![vec![12, 11]],
            vec![vec![9, 11]],
            vec![vec![11, 101]],
            vec![vec![10, 12], vec![12, 13]],
            vec![vec![10], vec![], vec![11]],
        ] {
            let listed = list_leaves(LISTING_BOUNDS, first, last, pages(refused.clone()), |_| {});
            assert!(listed.await.is_err(), "{refused:?}");
        }
    }

    /// A listing past its leaf, byte or time bound stops, so the subtree is
    /// walked instead.
    #[tokio::test]
    async fn a_listing_past_its_bounds_stops() {
        let (first, last) = (key(0), [0xff; 32]);
        let mut fetched = 0;
        let bounds = ListingBounds {
            leaves: 1_000,
            ..LISTING_BOUNDS
        };
        let listed = list_leaves(bounds, first, last, endless(100), |_| fetched += 1).await;
        assert!(matches!(listed, Ok(Listing::Bounded { leaves: 1_100, .. })));
        assert_eq!(fetched, 11);
        let bounds = ListingBounds {
            bytes: 10_000,
            ..LISTING_BOUNDS
        };
        let listed = list_leaves(bounds, first, last, endless(100), |_| {}).await;
        assert!(matches!(listed, Ok(Listing::Bounded { bytes: 13_200, .. })));
        let bounds = ListingBounds {
            deadline: Duration::ZERO,
            ..LISTING_BOUNDS
        };
        let listed = list_leaves(bounds, first, last, endless(100), |_| {}).await;
        assert!(matches!(listed, Ok(Listing::Bounded { leaves: 100, .. })));
    }

    /// An archive that stays busy is given up on after a while, so the sync
    /// can move to another archive.
    #[tokio::test]
    async fn a_persistently_busy_archive_is_given_up_on() {
        let result =
            retry_forest_read_within(Duration::from_millis(300), TIMEOUT_RETRIES, || async {
                Err::<(), _>(busy())
            })
            .await;
        assert!(result.unwrap_err().is_busy());
    }

    /// An archive whose listing pages step back within the range asked for
    /// kept the listing going for as long as it answered, every page held in
    /// memory before any check.
    #[test]
    fn reproduces_endless_forest_leaf_listing() {
        use quil_types::proto::global::{
            ForestLeaf, GetForestLeavesRequest, GetForestLeavesResponse,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tonic::codegen::http;

        /// Lists two leaves, the second below the first, with more to follow.
        struct SteppingBack(Arc<AtomicUsize>);

        impl tonic::server::UnaryService<GetForestLeavesRequest> for SteppingBack {
            type Response = GetForestLeavesResponse;
            type Future = futures::future::Ready<
                std::result::Result<tonic::Response<GetForestLeavesResponse>, tonic::Status>,
            >;

            fn call(&mut self, _: tonic::Request<GetForestLeavesRequest>) -> Self::Future {
                self.0.fetch_add(1, Ordering::SeqCst);
                let leaf = |byte: u8| ForestLeaf {
                    key_hash: vec![byte; 32],
                    value: vec![byte; 8],
                };
                futures::future::ready(Ok(tonic::Response::new(GetForestLeavesResponse {
                    leaves: vec![leaf(0x20), leaf(0x10)],
                    more: true,
                })))
            }
        }

        /// An archive's GlobalService answering every call as a listing.
        #[derive(Clone)]
        struct Archive(Arc<AtomicUsize>);

        impl tonic::server::NamedService for Archive {
            const NAME: &'static str = "quilibrium.node.global.pb.GlobalService";
        }

        impl tonic::codegen::Service<http::Request<tonic::body::BoxBody>> for Archive {
            type Response = http::Response<tonic::body::BoxBody>;
            type Error = std::convert::Infallible;
            type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

            fn poll_ready(
                &mut self,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn call(&mut self, request: http::Request<tonic::body::BoxBody>) -> Self::Future {
                let listing = SteppingBack(self.0.clone());
                Box::pin(async move {
                    let mut grpc = tonic::server::Grpc::new(tonic::codec::ProstCodec::default());
                    Ok(grpc.unary(listing, request).await)
                })
            }
        }

        struct Incoming(tokio::net::TcpListener);

        impl futures::Stream for Incoming {
            type Item = std::io::Result<tokio::net::TcpStream>;

            fn poll_next(
                self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                self.0
                    .poll_accept(cx)
                    .map(|result| Some(result.map(|(stream, _)| stream)))
            }
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let pages = Arc::new(AtomicUsize::new(0));
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let address = listener.local_addr().unwrap().to_string();
        runtime.spawn(
            tonic::transport::Server::builder()
                .add_service(Archive(pages.clone()))
                .serve_with_incoming(Incoming(listener)),
        );
        let client = runtime
            .block_on(ArchiveClient::connect_plaintext(&address))
            .unwrap();
        let reader = RemoteTreeReader::new(client, runtime.handle().clone(), vec![1; 32], 0);
        let (done, outcome) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let listed = quil_forest::BatchTreeReader::leaves_under(&reader, 1, &[false]);
            let _ = done.send(listed.map(|leaves| leaves.map(|leaves| leaves.len())));
        });
        let outcome = outcome.recv_timeout(Duration::from_secs(5));
        let served = pages.load(Ordering::SeqCst);
        runtime.shutdown_background();
        assert!(
            matches!(outcome, Ok(Err(_)) | Ok(Ok(None))),
            "listing pages stepping back within their range were still followed after 5 s: \
             {served} pages of two leaves listed ({outcome:?})"
        );
    }
}
