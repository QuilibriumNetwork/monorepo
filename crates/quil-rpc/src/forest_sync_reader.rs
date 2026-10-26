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
pub async fn fetch_in_batches<K, V, F, Fut>(keys: Vec<K>, fetch: F) -> std::result::Result<Vec<V>, ArchiveClientError>
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
        let before = self.reads.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        let reads = before + n as u64;
        let crossed = reads >= 1024 && (64 - before.leading_zeros()) != (64 - reads.leading_zeros());
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
            .block_on(async move { client.get_forest_value(shard_id, phase, max_version, kh).await })
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
        if error.is_unimplemented() && self.batched.swap(false, std::sync::atomic::Ordering::Relaxed) {
            tracing::info!("archive lacks batched forest reads (older build); reading one key per request");
            return true;
        }
        error.is_unimplemented()
    }

    async fn nodes(&self, keys: Vec<Vec<u8>>) -> std::result::Result<Vec<Option<Vec<u8>>>, ArchiveClientError> {
        let (client, shard_id, phase) = (self.client.clone(), self.shard_id.clone(), self.phase);
        if self.batched.load(std::sync::atomic::Ordering::Relaxed) {
            let fetched = fetch_in_batches(keys.clone(), |chunk: Vec<Vec<u8>>| {
                let (mut client, shard_id) = (client.clone(), shard_id.clone());
                async move { client.get_forest_nodes(shard_id, phase, chunk).await }
            }).await;
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
                        let (mut client, shard_id, key) = (client.clone(), shard_id.clone(), key.clone());
                        async move { client.get_forest_node(shard_id, phase, key).await }
                    }).await
                }
            })
            .buffered(REMOTE_BATCHES_IN_FLIGHT)
            .try_collect()
            .await
    }

    /// Every leaf in `[first, last]` at `version`, page by page.
    async fn listed(&self, version: u64, first: [u8; 32], last: [u8; 32])
        -> std::result::Result<Vec<(KeyHash, OwnedValue)>, ArchiveClientError> {
        let mut leaves: Vec<(KeyHash, OwnedValue)> = Vec::new();
        let mut after: Option<[u8; 32]> = None;
        loop {
            let (page, more) = retry_forest_read(|| {
                let (mut client, shard_id) = (self.client.clone(), self.shard_id.clone());
                async move { client.get_forest_leaves(shard_id, self.phase, version, first, last, after).await }
            }).await?;
            // Each page must continue past the last: a listing that does not
            // advance would never end. Its content is checked by the caller.
            if page.first().is_some_and(|(key, _)| after.is_some_and(|after| *key <= after)) || (more && page.is_empty()) {
                return Err(ArchiveClientError::MissingField("forest leaf listing did not advance"));
            }
            self.counted(page.len());
            after = page.last().map(|(key, _)| *key).or(after);
            leaves.extend(page.into_iter().map(|(key, value)| (KeyHash(key), value)));
            if !more {
                return Ok(leaves);
            }
        }
    }

    async fn values(&self, reads: Vec<(u64, Vec<u8>)>) -> std::result::Result<Vec<Option<Vec<u8>>>, ArchiveClientError> {
        let (client, shard_id, phase) = (self.client.clone(), self.shard_id.clone(), self.phase);
        if self.batched.load(std::sync::atomic::Ordering::Relaxed) {
            let fetched = fetch_in_batches(reads.clone(), |chunk: Vec<(u64, Vec<u8>)>| {
                let (mut client, shard_id) = (client.clone(), shard_id.clone());
                async move { client.get_forest_values(shard_id, phase, chunk).await }
            }).await;
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
                        let (mut client, shard_id, key) = (client.clone(), shard_id.clone(), key.clone());
                        async move { client.get_forest_value(shard_id, phase, version, key).await }
                    }).await
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
        let encoded = keys.iter().map(borsh::to_vec).collect::<std::io::Result<Vec<_>>>()?;
        let answers = self
            .handle
            .block_on(self.nodes(encoded))
            .map_err(|e| anyhow::anyhow!("remote get_forest_nodes: {e}"))?;
        answers
            .into_iter()
            .map(|bytes| bytes.map(|b| borsh::from_slice(&b)).transpose().map_err(Into::into))
            .collect()
    }

    fn leaves_under(&self, version: Version, bit_path: &[bool]) -> Result<Option<Vec<(KeyHash, OwnedValue)>>> {
        if !self.listing.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(None);
        }
        let (first, last) = quil_forest::key_range_under(bit_path);
        match self.handle.block_on(self.listed(version, first, last)) {
            Ok(leaves) => Ok(Some(leaves)),
            Err(e) if e.is_unimplemented() => {
                self.listing.store(false, std::sync::atomic::Ordering::Relaxed);
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
        let reads = reads.iter().map(|(version, key)| (*version, key.0.to_vec())).collect();
        self.handle
            .block_on(self.values(reads))
            .map_err(|e| anyhow::anyhow!("remote get_forest_values: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn busy() -> ArchiveClientError {
        ArchiveClientError::Rpc(tonic::Status::resource_exhausted("forest read workers busy; retry later"))
    }

    /// A read that outruns its deadline goes again a bounded number of
    /// times; an archive that keeps outrunning it fails the request.
    #[tokio::test]
    async fn timed_out_reads_are_sent_again_a_few_times() {
        let timeout = || ArchiveClientError::Rpc(tonic::Status::cancelled("Timeout expired"));
        assert!(timeout().is_timeout() && !timeout().is_busy() && !timeout().is_transport_failure());
        let calls = std::sync::atomic::AtomicUsize::new(0);
        let answered = retry_forest_read(|| {
            let n = calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async move { if n < 2 { Err(timeout()) } else { Ok(n) } }
        }).await;
        assert_eq!(answered.unwrap(), 2);
        calls.store(0, std::sync::atomic::Ordering::SeqCst);
        let failed: std::result::Result<(), _> = retry_forest_read(|| {
            calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            async { Err(timeout()) }
        }).await;
        assert!(failed.unwrap_err().is_timeout());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1 + TIMEOUT_RETRIES);
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
                    Ok(chunk.into_iter().take(100).map(|k| k * 2).collect::<Vec<_>>())
                }
            }
        };
        let answers = fetch_in_batches(keys.clone(), fetch).await.unwrap();
        assert_eq!(answers, keys.iter().map(|k| k * 2).collect::<Vec<_>>());
        assert!(calls.load(std::sync::atomic::Ordering::SeqCst) > 8);

        let empty = fetch_in_batches(vec![1u32], |_chunk: Vec<u32>| async { Ok(Vec::<u32>::new()) }).await;
        assert!(empty.is_err(), "an archive that answers nothing does not loop");
        let refused = fetch_in_batches(vec![1u32], |_chunk: Vec<u32>| async {
            Err::<Vec<u32>, _>(ArchiveClientError::Rpc(tonic::Status::unimplemented("old archive")))
        }).await;
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
        assert_eq!(largest.load(std::sync::atomic::Ordering::SeqCst), REMOTE_BATCH_KEYS / 8);
        // 256 → 128 → 64 → 32: three halvings, a few more from the batches
        // already in flight, not one per batch.
        assert!(timeouts.load(std::sync::atomic::Ordering::SeqCst) <= 3 * REMOTE_BATCHES_IN_FLIGHT);

        let stuck: std::result::Result<Vec<u32>, _> = fetch_in_batches(vec![1u32, 2], move |_chunk: Vec<u32>| async move {
            Err::<Vec<u32>, _>(timeout())
        }).await;
        assert!(stuck.unwrap_err().is_timeout(), "a link that answers not even one key gives up");
    }

    /// An archive that stays busy is given up on after a while, so the sync
    /// can move to another archive.
    #[tokio::test]
    async fn a_persistently_busy_archive_is_given_up_on() {
        let result = retry_forest_read_within(Duration::from_millis(300), TIMEOUT_RETRIES, || async { Err::<(), _>(busy()) }).await;
        assert!(result.unwrap_err().is_busy());
    }
}
