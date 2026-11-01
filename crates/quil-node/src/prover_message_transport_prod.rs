//! Production [`ProverMessageTransport`] impl.
//!
//! Fans bundle bytes out to every known archive over gRPC (mTLS via
//! the local Ed448 seed) and concurrently publishes the same bytes on
//! `GLOBAL_PROVER` via BlossomSub. Mirrors the previous inline logic
//! that lived in `ProverPipeline::publish_prover_message` before the
//! transport abstraction was introduced.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tracing::{debug, error, info, warn};

use quil_engine::prover_message_transport::ProverMessageTransport;
use quil_rpc::archive_client::ArchiveClientError;
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
/// archives of 2026-10-15, shard frames it could not verify yet), and storage
/// epoch proofs no archive took for any reason but a refusal for good (a
/// timeout, a failed connection), resent by one task per node. Each round
/// sends the queue oldest first and ends at the first message other than a
/// storage epoch proof that is still refused everywhere, so a stalled network
/// gets one submission per node per round rather than a resend of
/// everything, and an undelivered proof holds back no other message. A proof
/// goes to the archives one after another when sent again. Rounds
/// back off from 5 s to a minute. A message is given up after ten minutes, a
/// storage epoch proof once this node's GLOBAL frame reaches its window's
/// end, and either oldest first once the queue is full. Until 2026-10-15 a
/// refused submission was simply dropped: during the 880,560 halt every
/// regular's reward proofs and seals were lost. Until 2026-10-30 a storage
/// epoch proof that timed out on every archive was dropped too, and GLOBAL
/// kicked its prover at its window's end although it had proved in time.
#[derive(Default)]
pub(crate) struct SubmitRetryQueue {
    pending: std::sync::Mutex<VecDeque<Queued>>,
    running: AtomicBool,
    ids: AtomicU64,
}

/// One queued submission.
struct Queued {
    /// Its place in the queue: a later submission has a higher id.
    id: u64,
    bytes: Vec<u8>,
    queued: Instant,
    /// The storage epoch proof it carries.
    proof: Option<StorageProofSubmission>,
    /// Resends every archive failed.
    attempts: u32,
    /// When a failure to send it was last logged.
    logged: Instant,
}

#[derive(Clone, Copy)]
struct RetryTiming {
    first: Duration,
    longest: Duration,
    give_up: Duration,
    /// When a storage epoch proof is given up while this node knows no
    /// GLOBAL frame: its window ends at most two epochs after it began.
    proof_give_up: Duration,
    /// How often a storage epoch proof's failed resends are logged.
    proof_log_every: Duration,
}

const RETRY_TIMING: RetryTiming = RetryTiming {
    first: Duration::from_secs(5),
    longest: Duration::from_secs(60),
    give_up: Duration::from_secs(600),
    proof_give_up: Duration::from_secs(4 * 3600),
    proof_log_every: Duration::from_secs(300),
};
const RETRY_MAX_MESSAGES: usize = 256;
const RETRY_MAX_BYTES: usize = 32 << 20;

impl SubmitRetryQueue {
    /// Queue `bytes` (once), in place of the queued storage epoch proofs it
    /// covers; true if no worker is running and the caller must start one.
    fn push(&self, bytes: Vec<u8>) -> bool {
        let proof = StorageProofSubmission::of(&bytes);
        let mut pending = self.pending.lock().unwrap();
        if !pending.iter().any(|queued| queued.bytes == bytes) {
            if let Some(proof) = &proof {
                pending
                    .retain(|queued| !queued.proof.as_ref().is_some_and(|old| proof.covers(old)));
            }
            pending.push_back(Queued {
                id: self.ids.fetch_add(1, Ordering::Relaxed),
                bytes,
                queued: Instant::now(),
                proof,
                attempts: 0,
                // Its first failure was logged as it was queued.
                logged: Instant::now(),
            });
            let mut total: usize = pending.iter().map(|queued| queued.bytes.len()).sum();
            while pending.len() > RETRY_MAX_MESSAGES || total > RETRY_MAX_BYTES {
                let Some(dropped) = pending.pop_front() else {
                    break;
                };
                total -= dropped.bytes.len();
                warn!("prover submission retry queue full — dropping its oldest message");
            }
        }
        drop(pending);
        !self.running.swap(true, Ordering::AcqRel)
    }

    /// Drop the queued storage epoch proofs `delivered` covers, now that an
    /// archive took it; returns how many.
    fn delivered(&self, delivered: &StorageProofSubmission) -> usize {
        let mut pending = self.pending.lock().unwrap();
        let before = pending.len();
        pending.retain(|queued| {
            !queued
                .proof
                .as_ref()
                .is_some_and(|old| delivered.covers(old))
        });
        before - pending.len()
    }

    fn len(&self) -> usize {
        self.pending.lock().unwrap().len()
    }
}

/// The archives' answers to one submission.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Delivery {
    accepted: usize,
    /// Refusals that ask for a retry.
    retry: usize,
    /// The first archive's refusal, `<archive>: <reason>`.
    refusal: Option<String>,
}

/// An archive refusal that asks for a retry: `RESOURCE_EXHAUSTED`, or an
/// archive from before 2026-10-15 refusing a full mempool as an invalid
/// argument.
fn retryable(error: &quil_rpc::archive_client::ArchiveClientError) -> bool {
    match error {
        quil_rpc::archive_client::ArchiveClientError::Rpc(status) => {
            status.code() == tonic::Code::ResourceExhausted
                || (status.code() == tonic::Code::InvalidArgument
                    && status.message().contains("rank buffer full"))
        }
        _ => false,
    }
}

/// A failure that tells nothing about the message: the request outran its
/// deadline, the connection failed or went away, or the archive was
/// unavailable.
fn transient(error: &ArchiveClientError) -> bool {
    match error {
        ArchiveClientError::Rpc(status) => {
            matches!(
                status.code(),
                tonic::Code::Cancelled | tonic::Code::DeadlineExceeded | tonic::Code::Unavailable
            ) || error.is_transport_failure()
        }
        ArchiveClientError::Transport(_) | ArchiveClientError::TlsInit(_) => true,
        ArchiveClientError::InvalidEndpoint(_)
        | ArchiveClientError::MissingField(_)
        | ArchiveClientError::Tls(_) => false,
    }
}

/// Whether a submission `error` failed is sent again: a refusal asking for a
/// retry, and for a storage epoch proof (`proof`), whose window lasts an
/// epoch, any transient failure too.
fn asks_for_retry(error: &ArchiveClientError, proof: bool) -> bool {
    retryable(error) || (proof && transient(error))
}

/// Resend the queue until it empties. A round sends it oldest first and ends
/// at the first message other than a storage epoch proof still refused for
/// now everywhere. `frame` reads this node's latest GLOBAL frame, at which a
/// storage epoch proof's window ends.
async fn run_retries<F, Fut, G>(
    queue: Arc<SubmitRetryQueue>,
    timing: RetryTiming,
    submit: F,
    frame: G,
) where
    F: Fn(Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = Delivery>,
    G: Fn() -> Option<u64>,
{
    let mut delay = timing.first;
    loop {
        tokio::time::sleep(delay).await;
        let mut after = 0;
        let mut failed = false;
        loop {
            let next = {
                let frame = frame();
                let mut pending = queue.pending.lock().unwrap();
                expire(&mut pending, timing, frame);
                pending
                    .iter()
                    .find(|queued| queued.id >= after)
                    .map(|queued| (queued.id, queued.bytes.clone()))
            };
            let Some((id, bytes)) = next else {
                if failed {
                    break;
                }
                // Stop, unless a message was queued while this one ended.
                queue.running.store(false, Ordering::Release);
                if queue.pending.lock().unwrap().is_empty()
                    || queue.running.swap(true, Ordering::AcqRel)
                {
                    return;
                }
                continue;
            };
            let delivery = submit(bytes).await;
            after = id + 1;
            match resent(&queue, id, &delivery, timing, &frame) {
                Resent::Done => delay = timing.first,
                Resent::ProofFailed => failed = true,
                Resent::Failed => break,
            }
        }
        // The round ended at a message still undelivered.
        delay = (delay * 2).min(timing.longest);
    }
}

/// How a resend went.
enum Resent {
    /// Delivered, refused for good or no longer queued.
    Done,
    /// A storage epoch proof stays queued.
    ProofFailed,
    /// Another message stays queued.
    Failed,
}

/// Record the outcome of resending queued submission `id`.
fn resent(
    queue: &SubmitRetryQueue,
    id: u64,
    delivery: &Delivery,
    timing: RetryTiming,
    frame: &dyn Fn() -> Option<u64>,
) -> Resent {
    let mut pending = queue.pending.lock().unwrap();
    // Gone: a later proof covering it replaced it, or was delivered.
    let Some(index) = pending.iter().position(|queued| queued.id == id) else {
        return Resent::Done;
    };
    if delivery.accepted == 0 && delivery.retry > 0 {
        let queued = &mut pending[index];
        queued.attempts += 1;
        let Some(proof) = &queued.proof else {
            return Resent::Failed;
        };
        if queued.logged.elapsed() >= timing.proof_log_every {
            queued.logged = Instant::now();
            let (member, shards, epochs) = proof.fields();
            let (window_end, frames_left, mins_left) = proof.time_left(frame());
            warn!(member, ?shards, ?epochs, attempts = queued.attempts,
                secs = queued.queued.elapsed().as_secs(), reason = %refusal(delivery),
                window_end, %frames_left, %mins_left, consequence = proof.consequence(),
                "storage epoch proof still not delivered: no archive took it in time; sending it again until its window ends");
        }
        return Resent::ProofFailed;
    }
    let queued = pending.remove(index).expect("present");
    let Some(proof) = &queued.proof else {
        if delivery.accepted == 0 {
            warn!("queued prover submission refused for good — dropping");
        }
        return Resent::Done;
    };
    let (member, shards, epochs) = proof.fields();
    if delivery.accepted == 0 {
        // A send that timed out may have landed after all.
        warn!(member, ?shards, ?epochs, attempts = queued.attempts + 1, reason = %refusal(delivery),
            "storage epoch proof refused by every archive when sent again; an earlier send may have landed — not sent again");
        return Resent::Done;
    }
    let before = pending.len();
    pending.retain(|other| !other.proof.as_ref().is_some_and(|old| proof.covers(old)));
    let superseded = before - pending.len();
    drop(pending);
    let (window_end, frames_left, _) = proof.time_left(frame());
    info!(member, ?shards, ?epochs, accepted = delivery.accepted, attempts = queued.attempts + 1,
        secs = queued.queued.elapsed().as_secs(), window_end, %frames_left, superseded,
        "storage epoch proof delivered when sent again");
    Resent::Done
}

/// Drop what can no longer land: a message refused for `timing.give_up`, a
/// storage epoch proof once `frame`, this node's latest GLOBAL frame, is at
/// its window's end (or after `timing.proof_give_up` while none is known).
fn expire(pending: &mut VecDeque<Queued>, timing: RetryTiming, frame: Option<u64>) {
    let mut given_up = 0;
    pending.retain(|queued| {
        let Some(proof) = &queued.proof else {
            let keep = queued.queued.elapsed() < timing.give_up;
            given_up += usize::from(!keep);
            return keep;
        };
        let closed = match frame {
            Some(frame) => frame >= proof.window_end,
            None => queued.queued.elapsed() >= timing.proof_give_up,
        };
        if closed {
            let (member, shards, epochs) = proof.fields();
            error!(member, ?shards, ?epochs, window_end = proof.window_end, frame = %or_unknown(frame),
                attempts = queued.attempts + 1, secs = queued.queued.elapsed().as_secs(),
                consequence = proof.consequence(),
                "storage epoch proof undelivered when its window ended: no archive took it");
        }
        !closed
    });
    if given_up > 0 {
        warn!(
            given_up,
            "prover submissions still refused by every archive — giving up"
        );
    }
}

/// `value`, or "unknown".
fn or_unknown(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown".to_string(), |value| value.to_string())
}

/// A delivery's first refusal, for log lines.
fn refusal(delivery: &Delivery) -> &str {
    delivery.refusal.as_deref().unwrap_or("none")
}

/// This node's latest GLOBAL frame.
fn latest_frame(clock_store: &dyn ClockStore) -> Option<u64> {
    clock_store
        .get_latest_global_clock_frame()
        .ok()?
        .header
        .map(|header| header.frame_number)
}

/// Submit `bytes` to every archive in `pool` over mTLS, each request allowed
/// a deadline for its size (`quil_rpc::archive_client::submit_deadline`).
async fn submit_to_archives(
    pool: &ArchiveEndpointPool,
    seed: Option<Vec<u8>>,
    bytes: Vec<u8>,
) -> (usize, Delivery) {
    submit_to_archives_with(pool, seed, bytes, false).await
}

/// [`submit_to_archives`]; `resending_proof` sends a storage epoch proof again
/// (see [`fan_out_to_archives`]). A storage epoch proof is sent again after
/// any transient failure, and when no archive is known yet.
async fn submit_to_archives_with(
    pool: &ArchiveEndpointPool,
    seed: Option<Vec<u8>>,
    bytes: Vec<u8>,
    resending_proof: bool,
) -> (usize, Delivery) {
    let Some(seed) = seed else {
        return (0, Delivery::default());
    };
    let archive_addrs = pool.get_all().await;
    let archives = archive_addrs.len();
    let proof = carries_storage_proof(&bytes);
    let submit = move |stream_addr: String, bytes: Vec<u8>| {
        let seed = seed.clone();
        async move {
            match ArchiveClient::connect_mtls_for_submit(&stream_addr, &seed, bytes.len()).await {
                Ok(mut client) => match client.submit_global_message(bytes).await {
                    Ok(()) => Ok(stream_addr),
                    Err(e) => {
                        debug!(addr = %stream_addr, error = %e, "prover bundle submit rejected by archive");
                        let retry = asks_for_retry(&e, proof);
                        Err((
                            stream_addr,
                            format!("submit rejected: {}", refusal_reason(&e)),
                            retry,
                        ))
                    }
                },
                Err(e) => {
                    debug!(addr = %stream_addr, error = %e, "prover bundle submit: archive connect failed");
                    let retry = asks_for_retry(&e, proof);
                    Err((stream_addr, format!("connect failed: {e}"), retry))
                }
            }
        }
    };
    let mut delivery = fan_out_to_archives(archive_addrs, bytes, submit, resending_proof).await;
    if archives == 0 && proof {
        delivery.retry = 1;
        delivery.refusal = Some("no archive known yet".to_string());
    }
    (archives, delivery)
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
            tracing::warn!("all candidate archives timed out — falling back to local clock store",);
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
        let started = Instant::now();
        let proof = StorageProofSubmission::of(&bundle_bytes);
        let bytes = bundle_bytes.len();
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
            bs_handle
                .publish(GLOBAL_PROVER_BITMASK.to_vec(), bs_bytes)
                .await
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

        let outcome = combine_publish_outcome(
            archive_count,
            grpc_ok_count,
            publish_bs.then_some(&bs_result),
        );
        // Every archive refused it for now: resend it later.
        let queued = outcome.is_err() && delivery.retry > 0;
        if queued && self.retry_queue.push(bundle_bytes) {
            let (pool, seed) = (self.archive_pool.clone(), self.falcon_signing_key.clone());
            let clock_store = self.clock_store.clone();
            tokio::spawn(run_retries(
                self.retry_queue.clone(),
                RETRY_TIMING,
                move |bytes| {
                    let (pool, seed) = (pool.clone(), seed.clone());
                    let resending_proof = carries_storage_proof(&bytes);
                    async move {
                        submit_to_archives_with(&pool, seed, bytes, resending_proof)
                            .await
                            .1
                    }
                },
                move || latest_frame(clock_store.as_ref()),
            ));
        }
        if let Some(proof) = &proof {
            let (member, shards, epochs) = proof.fields();
            let (window_end, frames_left, mins_left) =
                proof.time_left(latest_frame(self.clock_store.as_ref()));
            if grpc_ok_count > 0 {
                let superseded = self.retry_queue.delivered(proof);
                info!(member, ?shards, ?epochs, bytes, accepted = grpc_ok_count, archives = archive_count,
                    secs = started.elapsed().as_secs_f64(), window_end, %frames_left, superseded,
                    "storage epoch proof delivered");
            } else if queued {
                warn!(member, ?shards, ?epochs, bytes, archives = archive_count,
                    deadline_secs = quil_rpc::archive_client::submit_deadline(bytes).as_secs(),
                    reason = %refusal(&delivery), window_end, %frames_left, %mins_left,
                    consequence = proof.consequence(),
                    "storage epoch proof not delivered: no archive took it in time; sending it again until its window ends");
            } else if outcome.is_err() {
                warn!(member, ?shards, ?epochs, bytes, archives = archive_count, reason = %refusal(&delivery),
                    "storage epoch proof refused by every archive — not sent again");
            }
        }
        if archive_count > 0 && grpc_ok_count == 0 && proof.is_none() {
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
                    publish_bs, "no archive accepted submission — message likely dropped"
                );
            }
        }
        if archive_count == 0 && !publish_bs {
            warn!("no archives discovered AND BlossomSub publish disabled — prover message has no delivery path");
        }

        match outcome {
            Err(QuilError::P2p(message)) if queued => {
                Err(QuilError::P2p(format!("{message}; queued to retry")))
            }
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
///
/// `resending_proof` sends to one archive after another, still all of them:
/// concurrent uploads share this node's uplink, so a proof too large for that
/// to carry to every archive within its deadline would time out everywhere at
/// each resend, and an archive holds what it took for its own proposals only.
/// Its refusals log at debug: the resends' summary names them.
async fn fan_out_to_archives<F, Fut>(
    archive_addrs: Vec<String>,
    bundle_bytes: Vec<u8>,
    submit: F,
    resending_proof: bool,
) -> Delivery
where
    F: Fn(String, Vec<u8>) -> Fut + Clone + Send + Sync + 'static,
    Fut: std::future::Future<Output = std::result::Result<String, (String, String, bool)>>
        + Send
        + 'static,
{
    let mut handles = Vec::with_capacity(archive_addrs.len());
    let mut results = Vec::with_capacity(archive_addrs.len());
    for addr in archive_addrs {
        // Archive peer-info multiaddrs use the pubsub port (:8336);
        // the gRPC stream service listens on :8340.
        let stream_addr = addr.replace(":8336", ":8340");
        let bytes = bundle_bytes.clone();
        let submit = submit.clone();
        // Parallel fan-out: each handle's result is awaited below, so
        // panics surface as JoinError and per-archive failures are
        // logged individually. This is the correct use of bare spawn.
        let handle = tokio::spawn(async move { submit(stream_addr, bytes).await });
        if resending_proof {
            results.push(handle.await);
        } else {
            handles.push(handle);
        }
    }
    for handle in handles {
        results.push(handle.await);
    }
    let mut delivery = Delivery::default();
    let mut refused = Vec::new();
    for result in results {
        match result {
            Ok(Ok(addr)) => {
                debug!(%addr, "prover message submitted via gRPC");
                delivery.accepted += 1;
            }
            Ok(Err((addr, reason, retry))) => {
                if retry {
                    delivery.retry += 1;
                }
                if delivery.refusal.is_none() {
                    delivery.refusal = Some(format!("{addr}: {reason}"));
                }
                refused.push((addr, reason, retry));
            }
            Err(e) => {
                warn!(error = %e, "gRPC submit task join error");
            }
        }
    }
    // A refusal another archive made up for loses nothing: summarize each
    // such archive at most every ARCHIVE_REFUSAL_EVERY, its reason naming
    // its state (a stale archive reports its executed frame against its
    // head). Without any acceptance, each refusal is a warning naming the
    // request.
    if !refused.is_empty() {
        let request = describe_bundle(&bundle_bytes);
        for (addr, reason, retry) in refused {
            if delivery.accepted == 0 {
                if resending_proof {
                    debug!(%addr, %reason, retry, %request, "gRPC submit failed");
                } else {
                    warn!(%addr, %reason, retry, %request, "gRPC submit failed");
                }
                continue;
            }
            let now = Instant::now();
            let summary = archive_refusals()
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .note(now, &addr);
            if let Some((refusals, secs)) = summary {
                info!(
                    scope = "peer",
                    archive = %addr,
                    refusals,
                    secs,
                    %reason,
                    %request,
                    "an archive refused prover submissions another archive accepted"
                );
            }
        }
    }
    delivery
}

/// How often an archive's refusals of submissions another archive accepted
/// are summarized again.
const ARCHIVE_REFUSAL_EVERY: Duration = Duration::from_secs(600);

/// Refusals per archive since its last summary line.
#[derive(Debug, Default)]
struct ArchiveRefusals {
    archives: std::collections::HashMap<String, (Instant, u64)>,
}

impl ArchiveRefusals {
    /// Count one refusal by `archive`; returns the refusals and seconds
    /// since its last line when one is due (its first refusal at once).
    fn note(&mut self, now: Instant, archive: &str) -> Option<(u64, u64)> {
        let Some((logged, count)) = self.archives.get_mut(archive) else {
            self.archives.insert(archive.to_string(), (now, 0));
            return Some((1, 0));
        };
        *count += 1;
        let secs = now.duration_since(*logged);
        if secs < ARCHIVE_REFUSAL_EVERY {
            return None;
        }
        let refusals = std::mem::take(count);
        *logged = now;
        Some((refusals, secs.as_secs()))
    }
}

fn archive_refusals() -> &'static std::sync::Mutex<ArchiveRefusals> {
    static REFUSALS: std::sync::OnceLock<std::sync::Mutex<ArchiveRefusals>> =
        std::sync::OnceLock::new();
    REFUSALS.get_or_init(Default::default)
}

/// An archive's refusal without the transport's metadata: the gRPC code and
/// the archive's message.
fn refusal_reason(error: &quil_rpc::archive_client::ArchiveClientError) -> String {
    match error {
        quil_rpc::archive_client::ArchiveClientError::Rpc(status) => {
            format!("{:?}: {}", status.code(), status.message())
        }
        other => other.to_string(),
    }
}

/// What a bundle carries, for its failure lines: each request's type, and a
/// shard frame header's shard and frame (`frame header <filter>@<frame>`).
fn describe_bundle(bundle: &[u8]) -> String {
    use quil_execution::global_intrinsic::frame_header::{FrameHeader, TYPE_FRAME_HEADER};
    use quil_execution::message_envelope::CanonicalMessageBundle;
    let Ok(bundle) = CanonicalMessageBundle::from_canonical_bytes(bundle) else {
        return "undecodable bundle".to_string();
    };
    bundle
        .requests
        .iter()
        .flatten()
        .map(|request| match request.inner_type_prefix {
            TYPE_FRAME_HEADER => match FrameHeader::from_canonical_bytes(&request.inner_bytes) {
                Ok(header) => format!(
                    "frame header {}@{}",
                    hex::encode(&header.address),
                    header.frame_number
                ),
                Err(_) => "frame header".to_string(),
            },
            prefix => format!("request type {prefix:#06x}"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether `bundle` carries a storage epoch proof.
fn carries_storage_proof(bundle: &[u8]) -> bool {
    use quil_execution::global_intrinsic::storage_epoch_proof::TYPE_STORAGE_EPOCH_PROOF;
    use quil_execution::message_envelope::CanonicalMessageBundle;
    CanonicalMessageBundle::from_canonical_bytes(bundle).is_ok_and(|bundle| {
        bundle
            .requests
            .iter()
            .flatten()
            .any(|request| request.inner_type_prefix == TYPE_STORAGE_EPOCH_PROOF)
    })
}

/// The storage epoch proof a submission carries: its member, its seats and
/// the GLOBAL frame from which GLOBAL refuses it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct StorageProofSubmission {
    member: [u8; 32],
    /// Each seat's shard filter, the epoch it settles, and whether it seals
    /// (the registration two epochs on) and settles.
    seats: Vec<(Vec<u8>, u64, bool, bool)>,
    /// The end of its earliest seat's window: a settlement's window ends as
    /// the epoch after the next begins, and a seal's as the epoch it seals
    /// begins, the same frame (`storage_epoch_proof::check`).
    window_end: u64,
}

impl StorageProofSubmission {
    fn of(bundle: &[u8]) -> Option<Self> {
        use quil_execution::global_intrinsic::storage_epoch_proof::{
            StorageEpochProof, TYPE_STORAGE_EPOCH_PROOF,
        };
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        use quil_execution::message_envelope::CanonicalMessageBundle;
        let bundle = CanonicalMessageBundle::from_canonical_bytes(bundle).ok()?;
        let request = bundle
            .requests
            .iter()
            .flatten()
            .find(|request| request.inner_type_prefix == TYPE_STORAGE_EPOCH_PROOF)?;
        let proof = StorageEpochProof::from_canonical_bytes(&request.inner_bytes).ok()?;
        let window_end = proof
            .seats
            .iter()
            .flat_map(|seat| {
                let settles = seat.settles.then(|| settlement_window(seat.epoch).1);
                let seals = seat
                    .seals
                    .then(|| quil_types::consensus::epoch_start_frame(seat.seal_epoch()));
                settles.into_iter().chain(seals)
            })
            .min()?;
        Some(Self {
            member: proof.member,
            seats: proof
                .seats
                .iter()
                .map(|seat| {
                    (
                        seat.shard_filter.clone(),
                        seat.epoch,
                        seat.seals,
                        seat.settles,
                    )
                })
                .collect(),
            window_end,
        })
    }

    /// Whether `other` is needless once this is delivered: the same member,
    /// and each of its seats sealed or settled here for the same epoch.
    fn covers(&self, other: &Self) -> bool {
        self.member == other.member
            && other.seats.iter().all(|(shard, epoch, seals, settles)| {
                self.seats.iter().any(|(s, e, se, st)| {
                    s == shard && e == epoch && (*se || !seals) && (*st || !settles)
                })
            })
    }

    /// Its member, shards and epochs, for log lines.
    fn fields(&self) -> (String, Vec<String>, Vec<u64>) {
        let mut epochs: Vec<u64> = self.seats.iter().map(|seat| seat.1).collect();
        epochs.sort_unstable();
        epochs.dedup();
        (
            hex::encode(self.member),
            self.seats.iter().map(|seat| hex::encode(&seat.0)).collect(),
            epochs,
        )
    }

    /// Its window's end, and the frames and estimated minutes left at
    /// `frame`.
    fn time_left(&self, frame: Option<u64>) -> (u64, String, String) {
        let frames = frame.map(|frame| self.window_end.saturating_sub(frame));
        let mins = frames.map(|frames| {
            frames.saturating_mul(quil_types::consensus::ideal_frame_time_ms()) / 60_000
        });
        (self.window_end, or_unknown(frames), or_unknown(mins))
    }

    /// What follows if no archive takes it before its window ends.
    fn consequence(&self) -> &'static str {
        if self.seats.iter().any(|seat| seat.3) {
            "unless an archive takes it before the window ends, GLOBAL withholds this prover's storage share on these shards (before epoch 1342: kicks it)"
        } else {
            "unless an archive takes it before the window ends, the registrations it seals stay unsealed"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        asks_for_retry, combine_publish_outcome, describe_bundle, fan_out_to_archives,
        refusal_reason, retryable, run_retries, submit_to_archives, submit_to_archives_with,
        ArchiveRefusals, Delivery, RetryTiming, StorageProofSubmission, SubmitRetryQueue,
        ARCHIVE_REFUSAL_EVERY,
    };
    use quil_types::error::QuilError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn publish_errors_distinguish_skipped_and_failed_paths() {
        let disabled = combine_publish_outcome(7, 0, None).unwrap_err().to_string();
        assert!(disabled.contains("no archive accepted submission; BlossomSub publish disabled"));
        assert!(!disabled.contains("BlossomSub publish failed"));
        let absent = combine_publish_outcome(0, 0, None).unwrap_err().to_string();
        assert!(absent.contains("no archives discovered; BlossomSub publish disabled"));
        let failed = Err(QuilError::P2p("topic mesh unavailable".into()));
        let attempted = combine_publish_outcome(7, 0, Some(&failed))
            .unwrap_err()
            .to_string();
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
        let ok = fan_out_to_archives(addrs, vec![0xAA; 16], submit, false)
            .await
            .accepted;
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
        let ok = fan_out_to_archives(addrs, vec![], submit, false)
            .await
            .accepted;
        assert_eq!(ok, 2, "expected 2 successful, 1 failure");
    }

    #[tokio::test]
    async fn publish_prover_message_all_archives_fail() {
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            Err::<String, (String, String, bool)>((addr, "simulated reject".to_string(), false))
        };
        let addrs = vec!["1.2.3.4:8336".to_string()];
        let ok = fan_out_to_archives(addrs, vec![], submit, false)
            .await
            .accepted;
        assert_eq!(ok, 0, "expected 0 successful submissions");
    }

    #[tokio::test]
    async fn publish_prover_message_empty_archive_list() {
        let submit = move |addr: String, _bytes: Vec<u8>| async move {
            Ok::<String, (String, String, bool)>(addr)
        };
        let ok = fan_out_to_archives(vec![], vec![], submit, false).await;
        assert_eq!(
            ok,
            Delivery::default(),
            "expected 0 successful submissions with empty list"
        );
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
        let delivery = fan_out_to_archives(
            vec!["a".into(), "b".into(), "c".into()],
            vec![],
            submit,
            false,
        )
        .await;
        assert_eq!(
            delivery,
            Delivery {
                accepted: 1,
                retry: 1,
                refusal: Some("b: rank buffer full".to_string()),
            }
        );
    }

    #[test]
    fn a_full_or_unverifiable_mempool_asks_for_a_retry() {
        use quil_rpc::archive_client::ArchiveClientError;
        let rpc = |status: tonic::Status| ArchiveClientError::Rpc(status);
        assert!(retryable(&rpc(tonic::Status::resource_exhausted(
            "submit rejected: shard frame verification unavailable"
        ))));
        // Archives from before the change refused a full mempool this way.
        assert!(retryable(&rpc(tonic::Status::invalid_argument(
            "submit rejected: message collector rejected: rank buffer full (rank 0, executed 0, head 880560)"
        ))));
        assert!(!retryable(&rpc(tonic::Status::invalid_argument(
            "submit rejected: shard frame failed verification"
        ))));
        assert!(!retryable(&ArchiveClientError::MissingField("data")));
    }

    const FAST: RetryTiming = RetryTiming {
        first: Duration::from_millis(5),
        longest: Duration::from_millis(20),
        give_up: Duration::from_secs(60),
        proof_give_up: Duration::from_secs(60),
        proof_log_every: Duration::from_secs(60),
    };

    #[tokio::test]
    async fn queued_submissions_are_resent_oldest_first_until_accepted() {
        let queue = Arc::new(SubmitRetryQueue::default());
        assert!(
            queue.push(b"one".to_vec()),
            "the first push starts the worker"
        );
        assert!(!queue.push(b"two".to_vec()));
        assert!(!queue.push(b"one".to_vec()), "queued once");
        assert_eq!(queue.len(), 2);
        let sent = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let log = sent.clone();
        run_retries(
            queue.clone(),
            FAST,
            move |bytes| {
                let log = log.clone();
                async move {
                    let mut log = log.lock().unwrap();
                    log.push(bytes);
                    // Archives are full for the first two rounds.
                    if log.len() <= 2 {
                        Delivery {
                            accepted: 0,
                            retry: 5,
                            ..Default::default()
                        }
                    } else {
                        Delivery {
                            accepted: 1,
                            ..Default::default()
                        }
                    }
                }
            },
            || None,
        )
        .await;
        let sent = sent.lock().unwrap().clone();
        assert_eq!(
            sent,
            vec![
                b"one".to_vec(),
                b"one".to_vec(),
                b"one".to_vec(),
                b"two".to_vec()
            ],
            "a round ends at the first message still refused"
        );
        assert_eq!(queue.len(), 0);
        assert!(
            queue.push(b"three".to_vec()),
            "an emptied queue's worker has stopped"
        );
    }

    #[tokio::test]
    async fn a_refusal_for_good_or_an_old_message_is_dropped() {
        let queue = Arc::new(SubmitRetryQueue::default());
        queue.push(b"invalid".to_vec());
        run_retries(
            queue.clone(),
            FAST,
            |_| async { Delivery::default() },
            || None,
        )
        .await;
        assert_eq!(queue.len(), 0);
        queue.push(b"stale".to_vec());
        let expired = RetryTiming {
            give_up: Duration::ZERO,
            ..FAST
        };
        run_retries(
            queue.clone(),
            expired,
            |_| async { unreachable!("an expired message is not sent") },
            || None,
        )
        .await;
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn failure_lines_name_the_request() {
        use quil_execution::global_intrinsic::frame_header::FrameHeader;
        let header = FrameHeader {
            address: vec![7; 4],
            frame_number: 9,
            ..Default::default()
        }
        .to_canonical_bytes()
        .unwrap();
        let bundle = crate::master_node::reward_proofs::prover_bundle(header).unwrap();
        assert_eq!(describe_bundle(&bundle), "frame header 07070707@9");
        let mut join = quil_execution::global_intrinsic::TYPE_PROVER_JOIN
            .to_be_bytes()
            .to_vec();
        join.extend_from_slice(b"join");
        let bundle = crate::master_node::reward_proofs::prover_bundle(join).unwrap();
        assert_eq!(
            describe_bundle(&bundle),
            format!(
                "request type {:#06x}",
                quil_execution::global_intrinsic::TYPE_PROVER_JOIN
            )
        );
        assert_eq!(describe_bundle(b"junk"), "undecodable bundle");
        let refused = quil_rpc::archive_client::ArchiveClientError::Rpc(
            tonic::Status::invalid_argument("rank buffer full"),
        );
        assert_eq!(
            refusal_reason(&refused),
            "InvalidArgument: rank buffer full"
        );
    }

    #[test]
    fn an_archive_refusing_what_another_accepted_is_summarized_every_interval() {
        let mut refusals = ArchiveRefusals::default();
        let t = std::time::Instant::now();
        assert_eq!(
            refusals.note(t, "a:8340"),
            Some((1, 0)),
            "its first refusal logs at once"
        );
        for n in 1..=5 {
            assert_eq!(refusals.note(t + Duration::from_secs(n), "a:8340"), None);
        }
        assert_eq!(
            refusals.note(t + Duration::from_secs(2), "b:8340"),
            Some((1, 0)),
            "archives are counted apart"
        );
        assert_eq!(
            refusals.note(t + ARCHIVE_REFUSAL_EVERY, "a:8340"),
            Some((6, 600))
        );
        assert_eq!(
            refusals.note(t + ARCHIVE_REFUSAL_EVERY + Duration::from_secs(1), "a:8340"),
            None
        );
    }

    /// A bundle of one storage epoch proof by `member` for `shard`: settling
    /// `epoch` and/or sealing its registration two epochs on, with a proof
    /// of `proof_bytes` bytes.
    fn storage_proof_bundle(
        member: u8,
        seats: &[(u8, u64, bool, bool)],
        proof_bytes: usize,
    ) -> Vec<u8> {
        use quil_execution::global_intrinsic::storage_epoch_proof::{SeatProof, StorageEpochProof};
        let proof = StorageEpochProof {
            member: [member; 32],
            seats: seats
                .iter()
                .map(|&(shard, epoch, seals, settles)| SeatProof {
                    shard_filter: vec![shard; 35],
                    epoch,
                    seals,
                    settles,
                    ..Default::default()
                })
                .collect(),
            proof: vec![0x5a; proof_bytes],
        };
        crate::master_node::reward_proofs::prover_bundle(proof.to_canonical_bytes()).unwrap()
    }

    /// An archive's peer listener (a PQNoise handshake, then `GlobalService`)
    /// taking every submission, behind a link that carries at most `rate`
    /// bytes a second toward it. Returns the link's address and the count of
    /// submissions the archive took.
    async fn archive_behind_slow_link(rate: usize) -> (String, Arc<AtomicUsize>) {
        archive_behind_link(Default::default(), rate).await
    }

    /// When a link is free next, for archives sharing it.
    type Link = Arc<std::sync::Mutex<Option<tokio::time::Instant>>>;

    /// [`archive_behind_slow_link`], over `link`, which other archives share.
    async fn archive_behind_link(link: Link, rate: usize) -> (String, Arc<AtomicUsize>) {
        use quil_types::proto::global::global_service_server::GlobalServiceServer;
        use quil_types::proto::global::GlobalFrame;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        struct NoFrames;
        impl quil_rpc::FrameLookup for NoFrames {
            fn get_latest_frame(&self) -> Result<GlobalFrame, String> {
                Err("no frames".into())
            }
            fn get_frame(&self, _frame_number: u64) -> Result<GlobalFrame, String> {
                Err("no frames".into())
            }
        }
        let taken = Arc::new(AtomicUsize::new(0));
        let handler: quil_rpc::SubmitHandler = {
            let taken = taken.clone();
            Arc::new(move |_request| {
                taken.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(()) })
            })
        };
        let server_key = quil_p2p::generate_falcon_signing_key();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let archive = listener.local_addr().unwrap();
        let (streams_tx, streams) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let (key, streams_tx) = (server_key.clone(), streams_tx.clone());
                tokio::spawn(async move {
                    if let Ok(stream) =
                        quil_rpc::pqnoise_channel::pq_server_handshake(tcp, &key).await
                    {
                        let _ = streams_tx.send(Ok::<_, std::io::Error>(stream));
                    }
                });
            }
        });
        let incoming = futures::stream::unfold(streams, |mut streams| async move {
            streams.recv().await.map(|stream| (stream, streams))
        });
        let service = GlobalServiceServer::new(
            quil_rpc::GlobalRpcServer::new(Arc::new(NoFrames)).with_submit_handler(handler),
        )
        .max_decoding_message_size(64 << 20);
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(incoming),
        );
        let front = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = front.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (client, _) = front.accept().await.unwrap();
                let link = link.clone();
                tokio::spawn(async move {
                    let Ok(upstream) = TcpStream::connect(archive).await else {
                        return;
                    };
                    let (mut client_read, mut client_write) = client.into_split();
                    let (mut upstream_read, mut upstream_write) = upstream.into_split();
                    tokio::spawn(async move {
                        let _ = tokio::io::copy(&mut upstream_read, &mut client_write).await;
                    });
                    let mut buffer = vec![0u8; 1024];
                    loop {
                        let n = match client_read.read(&mut buffer).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if upstream_write.write_all(&buffer[..n]).await.is_err() {
                            break;
                        }
                        let free = {
                            let mut free = link.lock().unwrap();
                            let now = tokio::time::Instant::now();
                            let next = free.map_or(now, |free| free.max(now))
                                + Duration::from_secs_f64(n as f64 / rate as f64);
                            *free = Some(next);
                            next
                        };
                        tokio::time::sleep_until(free).await;
                    }
                    let _ = upstream_write.shutdown().await;
                });
            }
        });
        (address, taken)
    }

    /// A 600 KB storage epoch proof sent over a link of 32 KiB/s takes about
    /// 19 s. A fixed 15 s request deadline cut it off on every archive
    /// (`Cancelled: Timeout expired`), and the proof was dropped; the
    /// deadline for its size lets it through.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_large_storage_proof_reaches_an_archive_over_a_slow_uplink() {
        let (address, taken) = archive_behind_slow_link(32 << 10).await;
        let pool = quil_rpc::ArchiveEndpointPool::new(Duration::ZERO);
        pool.add(address).await;
        let bundle = storage_proof_bundle(1, &[(7, 1335, false, true)], 600_000);
        let started = std::time::Instant::now();
        let (archives, delivery) =
            submit_to_archives(&pool, Some(quil_p2p::generate_falcon_signing_key()), bundle).await;
        let secs = started.elapsed().as_secs_f64();
        assert_eq!(archives, 1);
        assert_eq!(
            delivery.accepted, 1,
            "a 600 KB storage epoch proof over a 32 KiB/s link reached no archive \
             after {secs:.1} s: {delivery:?}"
        );
        assert_eq!(taken.load(Ordering::SeqCst), 1);
        assert!(secs > 15.0, "the link was not slow: {secs:.1} s");
    }

    /// Four archives share an uplink too slow to carry a 200 KB storage epoch
    /// proof to all of them within its deadline at once (25 s against 21 s):
    /// every upload times out, and would at each identical resend. Sent to
    /// one after another, each upload has the link to itself, and all four
    /// take it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_resent_storage_proof_reaches_every_archive_over_a_link_too_slow_for_all_at_once() {
        let link = Link::default();
        let pool = quil_rpc::ArchiveEndpointPool::new(Duration::ZERO);
        let mut taken = Vec::new();
        for _ in 0..4 {
            let (address, archive_took) = archive_behind_link(link.clone(), 32 << 10).await;
            pool.add(address).await;
            taken.push(archive_took);
        }
        let key = quil_p2p::generate_falcon_signing_key();
        let bundle = storage_proof_bundle(1, &[(7, 1335, false, true)], 200 * 1024);
        let (_, first) = submit_to_archives(&pool, Some(key.clone()), bundle.clone()).await;
        assert_eq!(
            (first.accepted, first.retry),
            (0, 4),
            "the first send, to all at once, times out everywhere: {first:?}"
        );
        let (_, resent) = submit_to_archives_with(&pool, Some(key), bundle, true).await;
        assert_eq!(
            resent.accepted, 4,
            "the resend, to one after another, reaches every archive: {resent:?}"
        );
        // An upload that timed out may still land from the socket buffers, so
        // an archive may see it twice; its collector answers a duplicate as
        // delivered.
        for archive_took in taken {
            assert!(archive_took.load(Ordering::SeqCst) >= 1);
        }
    }

    /// A storage epoch proof that every archive failed to take for a reason
    /// unrelated to it (a timeout, a failed connection) is sent again; other
    /// messages, and a refusal of the proof for good, are not.
    #[test]
    fn a_storage_proof_is_sent_again_after_a_timeout_or_a_failed_connection() {
        use quil_rpc::archive_client::ArchiveClientError;
        let timeout = ArchiveClientError::Rpc(tonic::Status::cancelled("Timeout expired"));
        let unavailable = ArchiveClientError::Rpc(tonic::Status::unavailable("connection reset"));
        let invalid = ArchiveClientError::Rpc(tonic::Status::invalid_argument(
            "submit rejected: epoch 1335 has nothing to settle",
        ));
        assert!(asks_for_retry(&timeout, true));
        assert!(asks_for_retry(&unavailable, true));
        assert!(!asks_for_retry(&invalid, true));
        assert!(!asks_for_retry(&timeout, false), "other messages as before");
        assert!(!asks_for_retry(&unavailable, false));
        let full = ArchiveClientError::Rpc(tonic::Status::resource_exhausted("full"));
        assert!(asks_for_retry(&full, false) && asks_for_retry(&full, true));
    }

    /// Over the real transport: an archive refusing connections leaves a
    /// storage epoch proof queued to retry, and any other message not.
    #[tokio::test]
    async fn an_unreachable_archive_queues_a_storage_proof_to_retry() {
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = closed.local_addr().unwrap().to_string();
        drop(closed);
        let pool = quil_rpc::ArchiveEndpointPool::new(Duration::ZERO);
        pool.add(address).await;
        let key = quil_p2p::generate_falcon_signing_key();
        let proof = storage_proof_bundle(1, &[(7, 1335, false, true)], 64);
        let (_, delivery) = submit_to_archives(&pool, Some(key.clone()), proof).await;
        assert_eq!((delivery.accepted, delivery.retry), (0, 1), "{delivery:?}");
        assert!(delivery.refusal.unwrap().contains("connect failed"));
        let header = crate::master_node::reward_proofs::prover_bundle(
            quil_execution::global_intrinsic::frame_header::FrameHeader::default()
                .to_canonical_bytes()
                .unwrap(),
        )
        .unwrap();
        let (_, delivery) = submit_to_archives(&pool, Some(key), header).await;
        assert_eq!((delivery.accepted, delivery.retry), (0, 0), "{delivery:?}");
    }

    /// A storage epoch proof no archive took is sent again until one takes
    /// it, and holds no other queued message back meanwhile.
    #[tokio::test]
    async fn a_storage_proof_that_timed_out_is_sent_again_until_an_archive_takes_it() {
        let queue = Arc::new(SubmitRetryQueue::default());
        let proof = storage_proof_bundle(1, &[(7, 1335, false, true)], 64);
        queue.push(proof.clone());
        queue.push(b"other".to_vec());
        let sent = Arc::new(std::sync::Mutex::new(Vec::<Vec<u8>>::new()));
        let log = sent.clone();
        let proof_sends = Arc::new(AtomicUsize::new(0));
        let submit = {
            let (proof, proof_sends) = (proof.clone(), proof_sends.clone());
            move |bytes: Vec<u8>| {
                log.lock().unwrap().push(bytes.clone());
                let timed_out = bytes == proof && proof_sends.fetch_add(1, Ordering::SeqCst) < 2;
                async move {
                    if timed_out {
                        Delivery {
                            retry: 1,
                            refusal: Some("a: submit rejected: Cancelled: Timeout expired".into()),
                            ..Default::default()
                        }
                    } else {
                        Delivery {
                            accepted: 1,
                            ..Default::default()
                        }
                    }
                }
            }
        };
        tokio::time::timeout(
            Duration::from_secs(10),
            run_retries(queue.clone(), FAST, submit, || Some(0)),
        )
        .await
        .expect("the queue empties");
        assert_eq!(
            *sent.lock().unwrap(),
            vec![proof.clone(), b"other".to_vec(), proof.clone(), proof],
            "the proof is sent until taken, the other message in its first round"
        );
        assert_eq!(queue.len(), 0);
    }

    /// A storage epoch proof is sent again for as long as its window lasts,
    /// beyond the ten minutes other messages get, and given up as this
    /// node's GLOBAL frame reaches its window's end.
    #[tokio::test]
    async fn a_storage_proof_is_given_up_when_its_window_ends() {
        let queue = Arc::new(SubmitRetryQueue::default());
        let bundle = storage_proof_bundle(1, &[(7, 1335, false, true)], 64);
        let window_end = StorageProofSubmission::of(&bundle).unwrap().window_end;
        queue.push(bundle);
        let frame = Arc::new(std::sync::atomic::AtomicU64::new(window_end - 3));
        let sends = Arc::new(AtomicUsize::new(0));
        let submit = {
            let (frame, sends) = (frame.clone(), sends.clone());
            move |_bytes: Vec<u8>| {
                sends.fetch_add(1, Ordering::SeqCst);
                frame.fetch_add(1, Ordering::SeqCst);
                async {
                    Delivery {
                        retry: 1,
                        ..Default::default()
                    }
                }
            }
        };
        let no_time = RetryTiming {
            give_up: Duration::ZERO,
            proof_give_up: Duration::ZERO,
            ..FAST
        };
        let reader = frame.clone();
        tokio::time::timeout(
            Duration::from_secs(10),
            run_retries(queue.clone(), no_time, submit, move || {
                Some(reader.load(Ordering::SeqCst))
            }),
        )
        .await
        .expect("given up at the window's end");
        assert_eq!(
            sends.load(Ordering::SeqCst),
            3,
            "sent at each of the window's last three frames"
        );
        assert_eq!(queue.len(), 0);
    }

    /// A storage epoch proof's window ends where GLOBAL refuses it: a
    /// settlement's with its settlement window, a seal's as the epoch it
    /// seals begins (the same frame). Other bundles carry none.
    #[test]
    fn a_storage_proofs_window_ends_where_global_refuses_it() {
        use quil_execution::global_intrinsic::storage_seat::settlement_window;
        let settles = storage_proof_bundle(1, &[(7, 1335, false, true)], 8);
        let seals = storage_proof_bundle(1, &[(7, 1335, true, false)], 8);
        let end = settlement_window(1335).1;
        assert_eq!(
            StorageProofSubmission::of(&settles).unwrap().window_end,
            end
        );
        assert_eq!(
            StorageProofSubmission::of(&seals).unwrap().window_end,
            quil_types::consensus::epoch_start_frame(1337)
        );
        assert_eq!(end, quil_types::consensus::epoch_start_frame(1337));
        let both = storage_proof_bundle(1, &[(7, 1336, false, true), (8, 1335, true, true)], 8);
        assert_eq!(StorageProofSubmission::of(&both).unwrap().window_end, end);
        let header = crate::master_node::reward_proofs::prover_bundle(
            quil_execution::global_intrinsic::frame_header::FrameHeader::default()
                .to_canonical_bytes()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(StorageProofSubmission::of(&header), None);
        assert!(!super::carries_storage_proof(&header));
        assert!(super::carries_storage_proof(&settles));
    }

    /// A later proof of the same seats replaces the queued one, and a
    /// delivered proof drops the queued proofs it covers, but no proof of
    /// another seat, epoch, part or member.
    #[test]
    fn a_proof_of_the_same_seats_replaces_or_settles_a_queued_one() {
        let queue = SubmitRetryQueue::default();
        queue.push(storage_proof_bundle(1, &[(7, 1335, false, true)], 8));
        queue.push(storage_proof_bundle(1, &[(7, 1335, false, true)], 9));
        assert_eq!(queue.len(), 1, "the later proof replaced the earlier");
        queue.push(storage_proof_bundle(1, &[(8, 1335, false, true)], 8));
        queue.push(storage_proof_bundle(1, &[(7, 1334, false, true)], 8));
        queue.push(storage_proof_bundle(1, &[(7, 1335, true, false)], 8));
        queue.push(storage_proof_bundle(2, &[(7, 1335, false, true)], 8));
        assert_eq!(queue.len(), 5);
        let delivered = StorageProofSubmission::of(&storage_proof_bundle(
            1,
            &[(7, 1335, false, true), (8, 1335, false, true)],
            8,
        ))
        .unwrap();
        assert_eq!(queue.delivered(&delivered), 2);
        assert_eq!(queue.len(), 3);
        let sealing_too =
            StorageProofSubmission::of(&storage_proof_bundle(1, &[(7, 1335, true, true)], 8))
                .unwrap();
        assert_eq!(queue.delivered(&sealing_too), 1, "the seal of 1335");
        assert_eq!(queue.len(), 2);
    }
}
