//! Production [`ProverMessageTransport`] impl.
//!
//! Fans bundle bytes out to every known archive over gRPC (mTLS via
//! the local Ed448 seed) and concurrently publishes the same bytes on
//! `GLOBAL_PROVER` via BlossomSub. Mirrors the previous inline logic
//! that lived in `ProverPipeline::publish_prover_message` before the
//! transport abstraction was introduced.

use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, warn};

use quil_engine::prover_message_transport::ProverMessageTransport;
use quil_rpc::{ArchiveClient, ArchiveEndpointPool};
use quil_types::error::{QuilError, Result};
use quil_types::proto::global::GlobalFrameHeader;
use quil_types::store::ClockStore;

const GLOBAL_PROVER_BITMASK: &[u8] = &[0x00, 0x00, 0x00];

/// Production transport: gRPC fan-out to archives, optionally also
/// BlossomSub publish.
pub struct ProdProverMessageTransport {
    pub archive_pool: Arc<ArchiveEndpointPool>,
    pub clock_store: Arc<dyn ClockStore>,
    pub p2p_handle: quil_p2p::node::P2PHandle,
    /// Ed448 seed for mTLS to archives. `None` when this node lacks an
    /// Ed448 identity (e.g. read-only client mode); in that case the
    /// gRPC fan-out is skipped and only BlossomSub carries the bundle.
    pub ed448_seed: Option<[u8; 57]>,
    /// When false, the BlossomSub publish on GLOBAL_PROVER is skipped
    /// and messages are sent exclusively via direct gRPC to archives.
    /// Non-archive nodes have no need to gossip prover messages — they
    /// don't subscribe to GLOBAL_PROVER either (matching Go).
    pub publish_to_blossomsub: bool,
}

#[async_trait]
impl ProverMessageTransport for ProdProverMessageTransport {
    async fn latest_global_frame_header(&self) -> Result<GlobalFrameHeader> {
        // Prefer a live archive read so the join's frame_number tracks
        // the network head (Go rejects joins where
        // `frame_number < head - 10`). Fall back to local store only
        // if no archive is reachable.
        if let Some(seed) = self.ed448_seed {
            if let Some(addr) = self.archive_pool.get_all().await.into_iter().next() {
                if let Ok(mut c) = ArchiveClient::connect_mtls(&addr, &seed).await {
                    if let Ok(f) = c.get_global_frame(0).await {
                        if let Some(h) = f.header.as_ref() {
                            return Ok(h.clone());
                        }
                    }
                }
            }
        }
        let f = self
            .clock_store
            .get_latest_global_clock_frame()
            .map_err(|e| QuilError::Internal(format!("no local frame: {e}")))?;
        let h = f
            .header
            .as_ref()
            .ok_or_else(|| QuilError::Internal("local frame missing header".into()))?;
        Ok(h.clone())
    }

    async fn publish_prover_bundle(&self, bundle_bytes: Vec<u8>) -> Result<()> {
        // Fan out to archives concurrently. Each closure connects + submits
        // independently so a slow / unreachable archive does not block the
        // others.
        let archive_addrs = if self.ed448_seed.is_some() {
            self.archive_pool.get_all().await
        } else {
            Vec::new()
        };
        let archive_count = archive_addrs.len();

        let grpc_future = {
            let bundle_bytes = bundle_bytes.clone();
            let seed_opt = self.ed448_seed;
            async move {
                if seed_opt.is_none() || archive_addrs.is_empty() {
                    return 0usize;
                }
                let seed = seed_opt.unwrap();
                let bytes = bundle_bytes;
                let submit = move |stream_addr: String, bytes: Vec<u8>| {
                    let seed = seed;
                    async move {
                        match ArchiveClient::connect_mtls(&stream_addr, &seed).await {
                            Ok(mut client) => match client.submit_global_message(bytes).await {
                                Ok(()) => Ok(stream_addr),
                                Err(e) => Err((stream_addr, format!("submit rejected: {e}"))),
                            },
                            Err(e) => Err((stream_addr, format!("connect failed: {e}"))),
                        }
                    }
                };
                fan_out_to_archives(archive_addrs, bytes, submit).await
            }
        };

        // BlossomSub publish runs concurrently with the gRPC fan-out
        // when enabled. Non-archive nodes skip the gossip publish
        // because they don't subscribe to GLOBAL_PROVER — publishing
        // into a topic you haven't joined is wasteful and unreliable.
        // Archive nodes publish on both paths for maximum dissemination.
        let publish_bs = self.publish_to_blossomsub;
        let bs_handle = self.p2p_handle.clone();
        let bs_bytes = bundle_bytes;
        let bs_future = async move {
            if !publish_bs {
                return Ok(());
            }
            bs_handle.publish(GLOBAL_PROVER_BITMASK.to_vec(), bs_bytes).await
        };

        let (grpc_ok_count, bs_result) = tokio::join!(grpc_future, bs_future);
        let p2p_ok = bs_result.is_ok();
        if let Err(ref e) = bs_result {
            warn!(error = %e, "BlossomSub publish failed for prover message");
        }

        if archive_count > 0 && grpc_ok_count == 0 {
            warn!(
                archive_count,
                "no archive accepted submission — relying on BlossomSub fallback"
            );
        }

        combine_publish_outcome(grpc_ok_count, p2p_ok)
    }
}

/// Combine fan-out outcomes into a final result. Returns `Err` only when
/// every archive failed AND the BlossomSub publish failed. Empty-mesh /
/// no-peer scenarios feed in as `p2p_ok = true` because the swarm
/// successfully accepted the message for buffered redelivery.
fn combine_publish_outcome(archive_ok_count: usize, p2p_ok: bool) -> Result<()> {
    if archive_ok_count == 0 && !p2p_ok {
        return Err(QuilError::P2p(
            "publish_prover_bundle: all paths failed (no archive accepted, BlossomSub publish failed)".into(),
        ));
    }
    Ok(())
}

/// Fan out a submission to every archive endpoint concurrently.
///
/// `submit` is a closure that takes a single `(stream_addr, payload)` and
/// returns `Ok(stream_addr)` on success or `Err((stream_addr, reason))`.
/// Returns the number of successful submissions.
async fn fan_out_to_archives<F, Fut>(
    archive_addrs: Vec<String>,
    bundle_bytes: Vec<u8>,
    submit: F,
) -> usize
where
    F: Fn(String, Vec<u8>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = std::result::Result<String, (String, String)>>
        + Send
        + 'static,
{
    let mut handles = Vec::with_capacity(archive_addrs.len());
    for addr in archive_addrs {
        // Archive peer-info multiaddrs use the pubsub port (:8336);
        // the gRPC stream service listens on :8340.
        let stream_addr = addr.replace(":8336", ":8340");
        let bytes = bundle_bytes.clone();
        let submit = submit.clone();
        // Parallel fan-out: each handle's result is awaited below, so
        // panics surface as JoinError and per-archive failures are
        // logged individually. This is the correct use of bare spawn.
        handles.push(tokio::spawn(async move { submit(stream_addr, bytes).await }));
    }
    let mut ok_count = 0usize;
    for h in handles {
        match h.await {
            Ok(Ok(addr)) => {
                debug!(%addr, "prover message submitted via gRPC");
                ok_count += 1;
            }
            Ok(Err((addr, reason))) => {
                warn!(%addr, %reason, "gRPC submit failed");
            }
            Err(e) => {
                warn!(error = %e, "gRPC submit task join error");
            }
        }
    }
    ok_count
}

#[cfg(test)]
mod tests {
    use super::fan_out_to_archives;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// Verify that fan-out attempts every archive and counts every success.
    #[tokio::test]
    async fn publish_prover_message_fans_out_to_all_archives() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let submit = move |addr: String, _bytes: Vec<u8>| {
            let calls = calls_clone.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<String, (String, String)>(addr)
            }
        };
        let addrs = vec![
            "1.2.3.4:8336".to_string(),
            "5.6.7.8:8336".to_string(),
            "9.10.11.12:8336".to_string(),
        ];
        let ok = fan_out_to_archives(addrs, vec![0xAA; 16], submit).await;
        assert_eq!(ok, 3, "expected 3 successful submissions");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "expected 3 closure invocations (one per archive)"
        );
    }

    #[tokio::test]
    async fn publish_prover_message_falls_back_when_one_archive_fails() {
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            if addr.starts_with("5.") {
                Err::<String, (String, String)>((addr, "simulated reject".to_string()))
            } else {
                Ok::<String, (String, String)>(addr)
            }
        };
        let addrs = vec![
            "1.2.3.4:8336".to_string(),
            "5.6.7.8:8336".to_string(),
            "9.10.11.12:8336".to_string(),
        ];
        let ok = fan_out_to_archives(addrs, vec![], submit).await;
        assert_eq!(ok, 2, "expected 2 successful, 1 failure");
    }

    #[tokio::test]
    async fn publish_prover_message_all_archives_fail() {
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            Err::<String, (String, String)>((addr, "simulated reject".to_string()))
        };
        let addrs = vec!["1.2.3.4:8336".to_string()];
        let ok = fan_out_to_archives(addrs, vec![], submit).await;
        assert_eq!(ok, 0, "expected 0 successful submissions");
    }

    #[tokio::test]
    async fn publish_prover_message_empty_archive_list() {
        let submit =
            move |addr: String, _bytes: Vec<u8>| async move { Ok::<String, (String, String)>(addr) };
        let ok = fan_out_to_archives(vec![], vec![], submit).await;
        assert_eq!(ok, 0, "expected 0 successful submissions with empty list");
    }
}
