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

/// Run `request` until it succeeds, retrying an archive that answers busy
/// (with backoff) and a connection that dropped (at once, a few times).
pub async fn retry_forest_read<T, F, Fut>(request: F) -> std::result::Result<T, ArchiveClientError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<T, ArchiveClientError>>,
{
    retry_forest_read_within(BUSY_RETRY_FOR, request).await
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
    mut request: F,
) -> std::result::Result<T, ArchiveClientError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = std::result::Result<T, ArchiveClientError>>,
{
    let started = std::time::Instant::now();
    let mut backoff = Duration::from_millis(200);
    let mut transport_retries = 0;
    loop {
        match request().await {
            Err(e) if e.is_busy() && started.elapsed() < busy_for => {
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
pub async fn fetch_in_batches<K, V, F, Fut>(keys: Vec<K>, fetch: F) -> std::result::Result<Vec<V>, ArchiveClientError>
where
    K: Clone + Send,
    F: Fn(Vec<K>) -> Fut + Clone,
    Fut: Future<Output = std::result::Result<Vec<V>, ArchiveClientError>>,
{
    let chunks: Vec<Vec<K>> = keys.chunks(REMOTE_BATCH_KEYS).map(<[K]>::to_vec).collect();
    let answers: Vec<Vec<V>> = stream::iter(chunks)
        .map(|chunk| {
            let fetch = fetch.clone();
            async move {
                let mut answered = Vec::with_capacity(chunk.len());
                while answered.len() < chunk.len() {
                    let rest = chunk[answered.len()..].to_vec();
                    let part = retry_forest_read(|| fetch(rest.clone())).await?;
                    if part.is_empty() || part.len() > rest.len() {
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

/// A remote view of ONE shard/phase tree on a peer archive, addressed by
/// `(shard_id, phase)`. Clone-cheap (the client shares one h2 channel).
pub struct RemoteTreeReader {
    client: ArchiveClient,
    handle: tokio::runtime::Handle,
    shard_id: Vec<u8>,
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
            shard_id,
            phase,
            reads: std::sync::atomic::AtomicU64::new(0),
            started: std::time::Instant::now(),
            batched: std::sync::atomic::AtomicBool::new(true),
            listing: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// Count remote reads (nodes or values). Log each time the count passes a
    /// power of two from 1,024, so a long walk shows progress in a few lines.
    fn counted(&self, n: usize) {
        let before = self.reads.fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        let reads = before + n as u64;
        let crossed = reads >= 1024 && (64 - before.leading_zeros()) != (64 - reads.leading_zeros());
        if crossed || (reads >= 1024 && reads.is_power_of_two()) {
            tracing::info!(
                shard = %hex::encode(&self.shard_id[..self.shard_id.len().min(8)]),
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

    /// An archive that stays busy is given up on after a while, so the sync
    /// can move to another archive.
    #[tokio::test]
    async fn a_persistently_busy_archive_is_given_up_on() {
        let result = retry_forest_read_within(Duration::from_millis(300), || async { Err::<(), _>(busy()) }).await;
        assert!(result.unwrap_err().is_busy());
    }
}
