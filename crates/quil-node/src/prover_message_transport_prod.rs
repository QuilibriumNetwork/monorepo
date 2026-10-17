//! Production [`ProverMessageTransport`] impl.
//!
//! Fans bundle bytes out to every known archive over gRPC (mTLS via
//! the local Ed448 seed) and concurrently publishes the same bytes on
//! `GLOBAL_PROVER` via BlossomSub. Mirrors the previous inline logic
//! that lived in `ProverPipeline::publish_prover_message` before the
//! transport abstraction was introduced.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    pub falcon_signing_key: Option<Vec<u8>>,
    /// When false, the BlossomSub publish on GLOBAL_PROVER is skipped
    /// and messages are sent exclusively via direct gRPC to archives.
    /// Non-archive nodes have no need to gossip prover messages — they
    /// don't subscribe to GLOBAL_PROVER either (matching Go).
    pub publish_to_blossomsub: bool,
    /// Submissions every archive refused only for now, resent later.
    pub(crate) retry_queue: Arc<SubmitRetryQueue>,
}

/// Submissions every archive refused only for now (a full mempool, or, from
/// archives of 2026-10-15, shard frames it could not verify yet), resent by
/// one task per node. Each round
/// sends the oldest first and ends while that is still refused everywhere,
/// so a stalled network gets one submission per node per round rather than
/// a resend of everything; rounds back off from 5 s to a minute. A message
/// is given up after ten minutes, or oldest first once the queue is full.
/// Until 2026-10-15 a refused submission was simply dropped: during the
/// 880,560 halt every regular's reward proofs and seals were lost.
#[derive(Default)]
pub(crate) struct SubmitRetryQueue {
    pending: std::sync::Mutex<VecDeque<(Vec<u8>, Instant)>>,
    running: AtomicBool,
}

#[derive(Clone, Copy)]
struct RetryTiming {
    first: Duration,
    longest: Duration,
    give_up: Duration,
}

const RETRY_TIMING: RetryTiming = RetryTiming {
    first: Duration::from_secs(5),
    longest: Duration::from_secs(60),
    give_up: Duration::from_secs(600),
};
const RETRY_MAX_MESSAGES: usize = 256;
const RETRY_MAX_BYTES: usize = 32 << 20;

impl SubmitRetryQueue {
    /// Queue `bytes` (once); true if no worker is running and the caller must
    /// start one.
    fn push(&self, bytes: Vec<u8>) -> bool {
        let mut pending = self.pending.lock().unwrap();
        if !pending.iter().any(|(queued, _)| *queued == bytes) {
            pending.push_back((bytes, Instant::now()));
            let mut total: usize = pending.iter().map(|(b, _)| b.len()).sum();
            while pending.len() > RETRY_MAX_MESSAGES || total > RETRY_MAX_BYTES {
                let Some((dropped, _)) = pending.pop_front() else { break };
                total -= dropped.len();
                warn!("prover submission retry queue full — dropping its oldest message");
            }
        }
        drop(pending);
        !self.running.swap(true, Ordering::AcqRel)
    }

    fn len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
}

/// The archives' answers to one submission.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Delivery {
    accepted: usize,
    /// Refusals that ask for a retry.
    retry: usize,
}

/// An archive refusal that asks for a retry: `RESOURCE_EXHAUSTED`, or an
/// archive from before 2026-10-15 refusing a full mempool as an invalid
/// argument.
fn retryable(error: &quil_rpc::archive_client::ArchiveClientError) -> bool {
    match error {
        quil_rpc::archive_client::ArchiveClientError::Rpc(status) => {
            status.code() == tonic::Code::ResourceExhausted
                || (status.code() == tonic::Code::InvalidArgument && status.message().contains("rank buffer full"))
        }
        _ => false,
    }
}

/// Resend the queue until it empties: each round sends the oldest message
/// first and stops at one still refused for now everywhere.
async fn run_retries<F, Fut>(queue: Arc<SubmitRetryQueue>, timing: RetryTiming, submit: F)
where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Delivery>,
{
    let mut delay = timing.first;
    loop {
        tokio::time::sleep(delay).await;
        loop {
            let next = {
                let mut pending = queue.pending.lock().unwrap();
                let before = pending.len();
                pending.retain(|(_, queued)| queued.elapsed() < timing.give_up);
                if pending.len() < before {
                    warn!(given_up = before - pending.len(), "prover submissions still refused by every archive — giving up");
                }
                pending.front().map(|(bytes, _)| bytes.clone())
            };
            let Some(bytes) = next else {
                // Stop, unless a message was queued while this one ended.
                queue.running.store(false, Ordering::Release);
                if queue.pending.lock().unwrap().is_empty() || queue.running.swap(true, Ordering::AcqRel) {
                    return;
                }
                continue;
            };
            let delivery = submit(bytes.clone()).await;
            if delivery.accepted == 0 && delivery.retry > 0 {
                delay = (delay * 2).min(timing.longest);
                break;
            }
            if delivery.accepted == 0 {
                warn!("queued prover submission refused for good — dropping");
            }
            let mut pending = queue.pending.lock().unwrap();
            if let Some(index) = pending.iter().position(|(queued, _)| *queued == bytes) {
                pending.remove(index);
            }
            delay = timing.first;
        }
    }
}

/// Submit `bytes` to every archive in `pool` over mTLS.
async fn submit_to_archives(
    pool: &ArchiveEndpointPool,
    seed: Option<Vec<u8>>,
    bytes: Vec<u8>,
) -> (usize, Delivery) {
    let Some(seed) = seed else { return (0, Delivery::default()) };
    let archive_addrs = pool.get_all().await;
    let archives = archive_addrs.len();
    let submit = move |stream_addr: String, bytes: Vec<u8>| {
        let seed = seed.clone();
        async move {
            match ArchiveClient::connect_mtls(&stream_addr, &seed).await {
                Ok(mut client) => match client.submit_global_message(bytes).await {
                    Ok(()) => Ok(stream_addr),
                    Err(e) => {
                        debug!(addr = %stream_addr, error = %e, "prover bundle submit rejected by archive");
                        let retry = retryable(&e);
                        Err((stream_addr, format!("submit rejected: {e}"), retry))
                    }
                },
                Err(e) => {
                    debug!(addr = %stream_addr, error = %e, "prover bundle submit: archive connect failed");
                    Err((stream_addr, format!("connect failed: {e}"), false))
                }
            }
        }
    };
    (archives, fan_out_to_archives(archive_addrs, bytes, submit).await)
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
        if let Some(seed) = self.falcon_signing_key.clone() {
            let addrs: Vec<String> = self
                .archive_pool
                .get_all()
                .await
                .into_iter()
                .take(MAX_ARCHIVES_TO_TRY)
                .collect();
            let mut handles = Vec::with_capacity(addrs.len());
            for addr in addrs {
                let seed_copy = seed.clone();
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
        let grpc_future = submit_to_archives(
            &self.archive_pool,
            self.falcon_signing_key.clone(),
            bundle_bytes.clone(),
        );

        // BlossomSub publish runs concurrently with the gRPC fan-out
        // when enabled. Non-archive nodes skip the gossip publish
        // because they don't subscribe to GLOBAL_PROVER — publishing
        // into a topic you haven't joined is wasteful and unreliable.
        // Archive nodes publish on both paths for maximum dissemination.
        let publish_bs = self.publish_to_blossomsub;
        let bs_handle = self.p2p_handle.clone();
        let bs_bytes = bundle_bytes.clone();
        let bs_future = async move {
            if !publish_bs {
                return Ok(());
            }
            bs_handle.publish(GLOBAL_PROVER_BITMASK.to_vec(), bs_bytes).await
        };

        let ((archive_count, delivery), bs_result) = tokio::join!(grpc_future, bs_future);
        let grpc_ok_count = delivery.accepted;
        // Only an attempted BlossomSub publish counts as a delivery path;
        // disabled publishing must not turn archive rejection into success.
        if publish_bs {
            if let Err(ref e) = bs_result {
                warn!(error = %e, "BlossomSub publish failed for prover message");
            }
        }

        let outcome = combine_publish_outcome(archive_count, grpc_ok_count, publish_bs.then_some(&bs_result));
        // Every archive refused it for now: resend it later.
        let queued = outcome.is_err() && delivery.retry > 0;
        if queued && self.retry_queue.push(bundle_bytes) {
            let (pool, seed) = (self.archive_pool.clone(), self.falcon_signing_key.clone());
            tokio::spawn(run_retries(self.retry_queue.clone(), RETRY_TIMING, move |bytes| {
                let (pool, seed) = (pool.clone(), seed.clone());
                async move { submit_to_archives(&pool, seed, bytes).await.1 }
            }));
        }
        if archive_count > 0 && grpc_ok_count == 0 {
            if queued {
                warn!(
                    archive_count,
                    full = delivery.retry,
                    queued = self.retry_queue.len(),
                    "no archive accepted submission yet — queued to retry"
                );
            } else {
                warn!(
                    archive_count,
                    publish_bs,
                    "no archive accepted submission — message likely dropped"
                );
            }
        }
        if archive_count == 0 && !publish_bs {
            warn!("no archives discovered AND BlossomSub publish disabled — prover message has no delivery path");
        }

        match outcome {
            Err(QuilError::P2p(message)) if queued => Err(QuilError::P2p(format!("{message}; queued to retry"))),
            outcome => outcome,
        }
    }
}

/// Report success if any archive accepted or an attempted BlossomSub publish
/// succeeded. A disabled BlossomSub path is not a failed publish.
fn combine_publish_outcome(
    archive_count: usize,
    archive_ok_count: usize,
    blossomsub_result: Option<&Result<()>>,
) -> Result<()> {
    if archive_ok_count > 0 || matches!(blossomsub_result, Some(Ok(()))) {
        return Ok(());
    }
    let archive_status = if archive_count == 0 {
        "no archives discovered"
    } else {
        "no archive accepted submission"
    };
    let blossomsub_status = match blossomsub_result {
        None => "BlossomSub publish disabled".to_string(),
        Some(Err(error)) => format!("BlossomSub publish failed: {error}"),
        Some(Ok(())) => unreachable!("successful publish returned above"),
    };
    Err(QuilError::P2p(format!(
        "publish_prover_bundle: {archive_status}; {blossomsub_status}"
    )))
}

/// Fan out a submission to every archive endpoint concurrently.
///
/// `submit` is a closure that takes a single `(stream_addr, payload)` and
/// returns `Ok(stream_addr)` on success or `Err((stream_addr, reason, retry))`.
/// Returns the successful submissions and the refusals asking for a retry.
async fn fan_out_to_archives<F, Fut>(
    archive_addrs: Vec<String>,
    bundle_bytes: Vec<u8>,
    submit: F,
) -> Delivery
where
    F: Fn(String, Vec<u8>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = std::result::Result<String, (String, String, bool)>>
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
    let mut delivery = Delivery::default();
    for h in handles {
        match h.await {
            Ok(Ok(addr)) => {
                debug!(%addr, "prover message submitted via gRPC");
                delivery.accepted += 1;
            }
            Ok(Err((addr, reason, retry))) => {
                if retry {
                    delivery.retry += 1;
                }
                warn!(%addr, %reason, retry, "gRPC submit failed");
            }
            Err(e) => {
                warn!(error = %e, "gRPC submit task join error");
            }
        }
    }
    delivery
}

#[cfg(test)]
mod tests {
    use super::{combine_publish_outcome, fan_out_to_archives, retryable, run_retries, Delivery, RetryTiming, SubmitRetryQueue};
    use std::time::Duration;
    use quil_types::error::QuilError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn publish_errors_distinguish_skipped_and_failed_paths() {
        let disabled = combine_publish_outcome(7, 0, None).unwrap_err().to_string();
        assert!(disabled.contains("no archive accepted submission; BlossomSub publish disabled"));
        assert!(!disabled.contains("BlossomSub publish failed"));
        let absent = combine_publish_outcome(0, 0, None).unwrap_err().to_string();
        assert!(absent.contains("no archives discovered; BlossomSub publish disabled"));
        let failed = Err(QuilError::P2p("topic mesh unavailable".into()));
        let attempted = combine_publish_outcome(7, 0, Some(&failed)).unwrap_err().to_string();
        assert!(attempted.contains("no archive accepted submission; BlossomSub publish failed:"));
        assert!(attempted.contains("topic mesh unavailable"));
        assert!(!attempted.contains("publish disabled"));
    }

    #[test]
    fn publish_success_still_requires_an_accepted_path() {
        let failed = Err(QuilError::P2p("topic mesh unavailable".into()));
        let succeeded = Ok(());
        assert!(combine_publish_outcome(7, 1, None).is_ok());
        assert!(combine_publish_outcome(7, 1, Some(&failed)).is_ok());
        assert!(combine_publish_outcome(0, 0, Some(&succeeded)).is_ok());
        assert!(combine_publish_outcome(7, 0, Some(&succeeded)).is_ok());
        assert!(combine_publish_outcome(7, 0, None).is_err());
        assert!(combine_publish_outcome(7, 0, Some(&failed)).is_err());
    }

    /// Verify that fan-out attempts every archive and counts every success.
    #[tokio::test]
    async fn publish_prover_message_fans_out_to_all_archives() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = calls.clone();
        let submit = move |addr: String, _bytes: Vec<u8>| {
            let calls = calls_clone.clone();
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok::<String, (String, String, bool)>(addr)
            }
        };
        let addrs = vec![
            "1.2.3.4:8336".to_string(),
            "5.6.7.8:8336".to_string(),
            "9.10.11.12:8336".to_string(),
        ];
        let ok = fan_out_to_archives(addrs, vec![0xAA; 16], submit).await.accepted;
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
                Err::<String, (String, String, bool)>((addr, "simulated reject".to_string(), false))
            } else {
                Ok::<String, (String, String, bool)>(addr)
            }
        };
        let addrs = vec![
            "1.2.3.4:8336".to_string(),
            "5.6.7.8:8336".to_string(),
            "9.10.11.12:8336".to_string(),
        ];
        let ok = fan_out_to_archives(addrs, vec![], submit).await.accepted;
        assert_eq!(ok, 2, "expected 2 successful, 1 failure");
    }

    #[tokio::test]
    async fn publish_prover_message_all_archives_fail() {
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            Err::<String, (String, String, bool)>((addr, "simulated reject".to_string(), false))
        };
        let addrs = vec!["1.2.3.4:8336".to_string()];
        let ok = fan_out_to_archives(addrs, vec![], submit).await.accepted;
        assert_eq!(ok, 0, "expected 0 successful submissions");
    }

    #[tokio::test]
    async fn publish_prover_message_empty_archive_list() {
        let submit =
            move |addr: String, _bytes: Vec<u8>| async move { Ok::<String, (String, String, bool)>(addr) };
        let ok = fan_out_to_archives(vec![], vec![], submit).await;
        assert_eq!(ok, Delivery::default(), "expected 0 successful submissions with empty list");
    }

    #[tokio::test]
    async fn fan_out_counts_refusals_that_ask_for_a_retry() {
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            match addr.as_str() {
                "a" => Ok::<String, (String, String, bool)>(addr),
                "b" => Err((addr, "rank buffer full".to_string(), true)),
                _ => Err((addr, "invalid".to_string(), false)),
            }
        };
        let delivery = fan_out_to_archives(vec!["a".into(), "b".into(), "c".into()], vec![], submit).await;
        assert_eq!(delivery, Delivery { accepted: 1, retry: 1 });
    }

    #[test]
    fn a_full_or_unverifiable_mempool_asks_for_a_retry() {
        use quil_rpc::archive_client::ArchiveClientError;
        let rpc = |status: tonic::Status| ArchiveClientError::Rpc(status);
        assert!(retryable(&rpc(tonic::Status::resource_exhausted("submit rejected: shard frame verification unavailable"))));
        // Archives from before the change refused a full mempool this way.
        assert!(retryable(&rpc(tonic::Status::invalid_argument(
            "submit rejected: message collector rejected: rank buffer full (rank 0, executed 0, head 880560)"
        ))));
        assert!(!retryable(&rpc(tonic::Status::invalid_argument("submit rejected: shard frame failed verification"))));
        assert!(!retryable(&ArchiveClientError::MissingField("data")));
    }

    const FAST: RetryTiming = RetryTiming {
        first: Duration::from_millis(5),
        longest: Duration::from_millis(20),
        give_up: Duration::from_secs(60),
    };

    #[tokio::test]
    async fn queued_submissions_are_resent_oldest_first_until_accepted() {
        let queue = Arc::new(SubmitRetryQueue::default());
        assert!(queue.push(b"one".to_vec()), "the first push starts the worker");
        assert!(!queue.push(b"two".to_vec()));
        assert!(!queue.push(b"one".to_vec()), "queued once");
        assert_eq!(queue.len(), 2);
        let sent = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let log = sent.clone();
        run_retries(queue.clone(), FAST, move |bytes| {
            let log = log.clone();
            async move {
                let mut log = log.lock().unwrap();
                log.push(bytes);
                // Archives are full for the first two rounds.
                if log.len() <= 2 { Delivery { accepted: 0, retry: 5 } } else { Delivery { accepted: 1, retry: 0 } }
            }
        })
        .await;
        let sent = sent.lock().unwrap().clone();
        assert_eq!(sent, vec![b"one".to_vec(), b"one".to_vec(), b"one".to_vec(), b"two".to_vec()],
            "a round ends at the first message still refused");
        assert_eq!(queue.len(), 0);
        assert!(queue.push(b"three".to_vec()), "an emptied queue's worker has stopped");
    }

    #[tokio::test]
    async fn a_refusal_for_good_or_an_old_message_is_dropped() {
        let queue = Arc::new(SubmitRetryQueue::default());
        queue.push(b"invalid".to_vec());
        run_retries(queue.clone(), FAST, |_| async { Delivery { accepted: 0, retry: 0 } }).await;
        assert_eq!(queue.len(), 0);
        queue.push(b"stale".to_vec());
        let expired = RetryTiming { give_up: Duration::ZERO, ..FAST };
        run_retries(queue.clone(), expired, |_| async { unreachable!("an expired message is not sent") }).await;
        assert_eq!(queue.len(), 0);
    }
}
