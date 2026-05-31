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
        //
        // Hard timeout per archive: a stalled mTLS handshake or
        // unresponsive gRPC server on the first archive would otherwise
        // wedge `submit_join` forever, because nothing else in the
        // lifecycle pipeline imposes a deadline. Symptom observed in
        // the wild: `prover lifecycle action ProposeJoin {...}` logs,
        // then complete silence — the next info! ("building ProverJoin")
        // never fires because the await above never resolves, the
        // join cooldown never re-arms, and ProposeJoin is silently
        // dead for the rest of the session.
        // Query archives in parallel and take the FRESHEST response.
        // Archives drift a few frames apart due to gossip; if we use
        // the first-to-respond, we may stamp the join with a
        // frame_number that's already stale at the leading archive,
        // tripping Go's `frame_number + 10 < current_frame` check at
        // verify time. The freshness budget gets eaten by VDF compute
        // (~2s), gRPC delivery, and Go's collector queue depth, so
        // every frame of staleness at the source matters.
        //
        // VDF challenge is `sha3(header.output)` so we can't mix
        // outputs from different archives — we pick ONE complete
        // header, just the freshest one available.
        const PER_ARCHIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        const MAX_ARCHIVES_TO_TRY: usize = 5;
        if let Some(seed) = self.ed448_seed {
            let addrs: Vec<String> = self
                .archive_pool
                .get_all()
                .await
                .into_iter()
                .take(MAX_ARCHIVES_TO_TRY)
                .collect();
            let mut handles = Vec::with_capacity(addrs.len());
            for addr in addrs {
                let seed_copy = seed;
                let addr_for_log = addr.clone();
                handles.push(tokio::spawn(async move {
                    let attempt = async {
                        let mut c = ArchiveClient::connect_mtls(&addr, &seed_copy).await.ok()?;
                        let f = c.get_global_frame(0).await.ok()?;
                        f.header.clone()
                    };
                    match tokio::time::timeout(PER_ARCHIVE_TIMEOUT, attempt).await {
                        Ok(Some(h)) => Some((addr_for_log, h)),
                        Ok(None) => {
                            tracing::debug!(
                                addr = %addr_for_log,
                                "archive returned no header"
                            );
                            None
                        }
                        Err(_) => {
                            tracing::warn!(
                                addr = %addr_for_log,
                                timeout_ms = PER_ARCHIVE_TIMEOUT.as_millis() as u64,
                                "archive frame-header fetch timed out",
                            );
                            None
                        }
                    }
                }));
            }
            let mut best: Option<(String, GlobalFrameHeader)> = None;
            for h in handles {
                if let Ok(Some((addr, header))) = h.await {
                    match &best {
                        None => best = Some((addr, header)),
                        Some((_, current)) if header.frame_number > current.frame_number => {
                            best = Some((addr, header));
                        }
                        _ => {}
                    }
                }
            }
            if let Some((addr, header)) = best {
                tracing::debug!(
                    %addr,
                    frame_number = header.frame_number,
                    "selected freshest archive header"
                );
                return Ok(header);
            }
            tracing::warn!(
                "all candidate archives timed out — falling back to local clock store",
            );
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
        // Non-archive nodes never publish on BlossomSub (they don't
        // subscribe to GLOBAL_PROVER), so for them BlossomSub cannot
        // count as a delivery path. Treat `p2p_ok` as true only when
        // we actually attempted a publish AND it succeeded.
        let p2p_ok = publish_bs && bs_result.is_ok();
        if publish_bs {
            if let Err(ref e) = bs_result {
                warn!(error = %e, "BlossomSub publish failed for prover message");
            }
        }

        if archive_count > 0 && grpc_ok_count == 0 {
            warn!(
                archive_count,
                publish_bs,
                "no archive accepted submission — message likely dropped"
            );
        }
        if archive_count == 0 && !publish_bs {
            warn!("no archives discovered AND BlossomSub publish disabled — prover message has no delivery path");
        }

        combine_publish_outcome(grpc_ok_count, p2p_ok)
    }
}

/// Combine fan-out outcomes into a final result. Returns `Err` only when
/// every archive failed AND the BlossomSub publish failed. `p2p_ok` is
/// only `true` when we actually attempted a BlossomSub publish AND the
/// swarm accepted the message (or had no peers but accepted for
/// buffered redelivery). Non-archive callers that skip the BlossomSub
/// path must pass `p2p_ok = false` so a zero-archive-accepted outcome
/// is correctly classified as a failure rather than a silent drop.
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
