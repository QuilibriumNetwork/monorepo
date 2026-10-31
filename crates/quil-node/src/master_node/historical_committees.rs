//! Rebuilds, from authenticated GLOBAL state, the committees that certified
//! legacy app frames (see `quil_engine::historical_committee`).
//!
//! A legacy frame's committee is `get_active_provers(filter, anchor)` as the
//! proposer's registry gave it, and that registry ran a few GLOBAL frames
//! ahead of the anchor (the proposer anchors `K` frames below its head). So
//! for each GLOBAL frame in a short window around the anchor, this reads the
//! prover tree as it stood after that frame and computes the committee there:
//!
//! 1. Header `n` commits the prover tree after frame `n - 1`
//!    (`prover_tree_commitment` for vertex-adds, `prover_tree_aux_roots` for
//!    the other phases). A header is taken from this node's clock store (held
//!    only after validation and canonical linkage) or fetched from an
//!    archive: a run of frames is accepted only up to a frame carrying its own
//!    GLOBAL finalization certificate, every frame validated (which binds the
//!    header's commitments into its output) and linked to the next by its
//!    parent selector.
//! 2. The tree at that root is synced into a scratch store, pinned to the
//!    committed root (an archive cannot substitute nodes); only phases the
//!    header pins are synced, so no phase reflects an archive's own choice.
//! 3. The registry is built from the scratch store and asked for the committee.
//!
//! Nothing here relaxes certificate verification: the validator still needs
//! a quorum of valid signatures over the frame, under one of these
//! committees, each of which existed at a frame near the anchor.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;

use quil_types::error::{QuilError, Result};
use quil_types::proto::global::{GlobalFrame, GlobalFrameHeader};
use tracing::{info, warn};

/// GLOBAL frames before the anchor whose post-state is tried (a proposer's
/// registry can lag its anchor).
const BEFORE: u64 = 2;
/// GLOBAL frames after the anchor whose post-state is tried (the proposer's
/// registry ran up to `K` = 4 frames ahead, plus margin).
const AFTER: u64 = 8;
/// Frames fetched above the newest needed header while looking for one that
/// carries its own certificate.
const MAX_RUN: u64 = 64;
/// Registries kept by prover root.
const KEPT_REGISTRIES: usize = 32;
/// Archives asked for one worker's GLOBAL anchor.
const ANCHOR_ARCHIVES: usize = 3;
/// One archive's answer to a GLOBAL anchor fetch, connection and the frames
/// above it included. Three of them fit the 10 s the gRPC server gives the
/// whole fetch.
const ANCHOR_FETCH: std::time::Duration = std::time::Duration::from_secs(3);
/// How far above an anchor without a certificate of its own a certified frame
/// linking down to it is sought (mainnet 883450's was the next frame, Oct 18).
const ANCHOR_DESCENT: u64 = 8;
/// How often a GLOBAL anchor no archive serves is warned about again. Each
/// blocked worker asks for it on every shard sync attempt, every few seconds.
const ANCHOR_WARN_REPEAT: std::time::Duration = std::time::Duration::from_secs(30 * 60);
/// GLOBAL frames whose last warning is remembered; the oldest is forgotten.
const ANCHOR_WARNED_KEPT: usize = 64;

/// Connects to an archive (`:8340` mTLS under the node's identity).
pub(crate) type ArchiveConnector = Arc<
    dyn Fn(
            String,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<quil_rpc::ArchiveClient>> + Send>,
        > + Send
        + Sync,
>;

pub(crate) struct HistoricalCommittees {
    pool: Arc<quil_rpc::ArchiveEndpointPool>,
    connect: ArchiveConnector,
    clock_store: Arc<quil_store::RocksClockStore>,
    frame_validate: quil_rpc::frame_sync::FrameValidator,
    verifier: Arc<quil_engine::frame_validator::GlobalFrameVerifier>,
    inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver>,
    scratch_dir: PathBuf,
    state: tokio::sync::Mutex<Scratch>,
    /// One GLOBAL anchor fetch at a time: workers blocked on the same frame
    /// find it stored once the first fetch lands.
    anchor_fetch: tokio::sync::Mutex<()>,
    anchor_warnings: std::sync::Mutex<AnchorWarnings>,
}

/// When each GLOBAL anchor no archive served was last warned about, so a
/// frame is warned about once per [`ANCHOR_WARN_REPEAT`], not per request.
#[derive(Default)]
struct AnchorWarnings {
    warned: std::collections::BTreeMap<u64, std::time::Instant>,
}

impl AnchorWarnings {
    /// Whether a failed fetch of `frame` at `now` is warned about: the first
    /// time and then once per [`ANCHOR_WARN_REPEAT`].
    fn due(&mut self, frame: u64, now: std::time::Instant) -> bool {
        if self
            .warned
            .get(&frame)
            .is_some_and(|at| now.saturating_duration_since(*at) < ANCHOR_WARN_REPEAT)
        {
            return false;
        }
        self.warned.insert(frame, now);
        while self.warned.len() > ANCHOR_WARNED_KEPT {
            let Some(oldest) = self
                .warned
                .iter()
                .min_by_key(|(_, at)| **at)
                .map(|(frame, _)| *frame)
            else {
                break;
            };
            self.warned.remove(&oldest);
        }
        true
    }

    /// `frame` was recovered: a later failure is new.
    fn recovered(&mut self, frame: u64) {
        self.warned.remove(&frame);
    }
}

#[derive(Default)]
struct Scratch {
    tree: Option<ScratchTree>,
    registries: VecDeque<([u8; 32], Arc<quil_execution::InMemoryProverRegistry>)>,
}

struct ScratchTree {
    db: Arc<quil_store::RocksDb>,
    crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    /// The vertex-removes phase holds a pinned historical tree.
    removes_synced: bool,
}

impl HistoricalCommittees {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        pool: Arc<quil_rpc::ArchiveEndpointPool>,
        key: Vec<u8>,
        clock_store: Arc<quil_store::RocksClockStore>,
        frame_validate: quil_rpc::frame_sync::FrameValidator,
        verifier: Arc<quil_engine::frame_validator::GlobalFrameVerifier>,
        inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver>,
        scratch_dir: PathBuf,
    ) -> Self {
        let connect: ArchiveConnector = Arc::new(move |addr: String| {
            let key = key.clone();
            Box::pin(async move {
                quil_rpc::ArchiveClient::connect_mtls(&addr, &key)
                    .await
                    .map_err(|e| QuilError::ExecutionUnavailable(format!("archive connect: {e}")))
            })
        });
        Self {
            pool,
            connect,
            clock_store,
            frame_validate,
            verifier,
            inclusion_prover,
            scratch_dir,
            state: tokio::sync::Mutex::new(Scratch::default()),
            anchor_fetch: tokio::sync::Mutex::new(()),
            anchor_warnings: std::sync::Mutex::new(AnchorWarnings::default()),
        }
    }

    #[cfg(test)]
    fn with_connector(mut self, connect: ArchiveConnector) -> Self {
        self.connect = connect;
        self
    }

    /// The distinct committees `filter` had at `anchor` under the prover tree
    /// after each GLOBAL frame in `[anchor - BEFORE, anchor + AFTER]`.
    pub(crate) async fn committees(&self, filter: &[u8], anchor: u64) -> Result<Vec<Vec<Vec<u8>>>> {
        let mut scratch = self.state.lock().await;
        // Header n commits the tree after frame n - 1.
        let lo = anchor.saturating_sub(BEFORE).max(1) + 1;
        let hi = anchor + AFTER + 1;
        let headers = self.authenticated_headers(lo, hi).await?;
        let mut seen = HashSet::new();
        let mut committees: Vec<Vec<Vec<u8>>> = Vec::new();
        for header in headers {
            let Ok(root) = <[u8; 32]>::try_from(header.prover_tree_commitment.as_slice()) else {
                continue;
            };
            if !seen.insert(root) {
                continue;
            }
            let registry = match self.registry_at(&mut scratch, &header, root).await {
                Ok(registry) => registry,
                Err(error) => {
                    warn!(frame = header.frame_number, root = %hex::encode(root), %error,
                        "historical committee: prover tree unavailable at this root");
                    continue;
                }
            };
            let members: Vec<Vec<u8>> = registry
                .get_active_provers(filter, anchor)
                .into_iter()
                .map(|prover| prover.public_key.clone())
                .collect();
            if !members.is_empty() && !committees.contains(&members) {
                committees.push(members);
            }
        }
        info!(filter = %hex::encode(filter), anchor, roots = seen.len(), committees = committees.len(),
            "historical committees rebuilt from the GLOBAL prover tree");
        Ok(committees)
    }

    /// Headers `lo..=hi`, each held locally or authenticated from an archive.
    async fn authenticated_headers(&self, lo: u64, hi: u64) -> Result<Vec<GlobalFrameHeader>> {
        let local: Vec<Option<GlobalFrameHeader>> = (lo..=hi)
            .map(|n| {
                self.clock_store
                    .get_global_frame(n)
                    .ok()
                    .and_then(|frame| frame.header)
            })
            .collect();
        if local.iter().all(Option::is_some) {
            return Ok(local.into_iter().flatten().collect());
        }
        let mut last_error = None;
        for addr in self.pool.get_all().await {
            match self.fetch_certified_run(&addr, lo, hi).await {
                Ok(headers) => return Ok(headers),
                Err(error) => {
                    warn!(peer = %addr, lo, hi, %error, "historical committee: GLOBAL headers unavailable from this archive");
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            QuilError::ExecutionUnavailable("no archive to fetch GLOBAL headers from".into())
        }))
    }

    /// Fetch frames from `lo` upward until one at or above `hi` carries its own
    /// certificate, then accept `lo..=hi` as its linked ancestors.
    async fn fetch_certified_run(
        &self,
        addr: &str,
        lo: u64,
        hi: u64,
    ) -> Result<Vec<GlobalFrameHeader>> {
        let mut client = (self.connect)(addr.to_string()).await?;
        let mut run: Vec<GlobalFrame> = Vec::new();
        for n in lo..=hi + MAX_RUN {
            let frame = match self.clock_store.get_global_frame(n) {
                Ok(frame) => frame,
                Err(_) => tokio::time::timeout(
                    std::time::Duration::from_secs(30),
                    client.get_global_frame(n),
                )
                .await
                .map_err(|_| {
                    QuilError::ExecutionUnavailable(format!("GLOBAL frame {n} fetch timed out"))
                })?
                .map_err(|e| QuilError::ExecutionUnavailable(format!("GLOBAL frame {n}: {e}")))?,
            };
            if frame.header.as_ref().map(|h| h.frame_number) != Some(n)
                || !(self.frame_validate)(&frame)
            {
                return Err(QuilError::InvalidArgument(format!(
                    "GLOBAL frame {n} failed validation"
                )));
            }
            let certified = n >= hi && self.self_certified(&frame);
            run.push(frame);
            if certified {
                return linked_headers(run, hi - lo + 1);
            }
        }
        Err(QuilError::ExecutionUnavailable(
            "no certified GLOBAL frame above the needed headers".into(),
        ))
    }

    /// GLOBAL frame `number` for this node's worker, which validates an app
    /// frame anchored to it: from this node's store, else fetched from an
    /// archive, accepted only when it passes the gossip check (genesis
    /// prover, VDF and signature) and is certified (`anchor_accepted`), and
    /// stored. Never the latest frame alias or a frame at or above this
    /// node's head; at most [`ANCHOR_ARCHIVES`] archives, each within
    /// [`ANCHOR_FETCH`]. Below this node's request-retention boundary only
    /// the header is fetched, as that is all the store keeps there.
    pub(crate) async fn global_anchor(&self, number: u64) -> Result<GlobalFrame> {
        let _one = self.anchor_fetch.lock().await;
        match self.clock_store.get_global_frame(number) {
            Ok(frame) => return Ok(frame),
            Err(QuilError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
        let head = self.clock_store.get_latest_frame_number().unwrap_or(0);
        if number == 0 || number >= head {
            return Err(QuilError::InvalidArgument(format!(
                "GLOBAL anchor {number} is not behind this node's head {head}"
            )));
        }
        // The worker validates against the header alone, but a frame stored
        // at or above the request-retention boundary counts as whole: the gap
        // backfill skips it and peers are served it. Below the boundary the
        // store keeps headers only and refuses them to peers, so a header is
        // all the anchor needs, and it spares the archive reading and sending
        // request bundles that can run to megabytes within `ANCHOR_FETCH`.
        let header_only = self
            .clock_store
            .global_requests_retained_from()
            .is_some_and(|from| number < from);
        let mut refusals = Vec::new();
        for addr in self.pool.get_all().await.into_iter().take(ANCHOR_ARCHIVES) {
            let fetched = tokio::time::timeout(ANCHOR_FETCH, async {
                let mut client = (self.connect)(addr.clone()).await?;
                let read = if header_only {
                    client.get_global_frame_header_only(number).await
                } else {
                    client.get_global_frame(number).await
                };
                let frame = read
                    .map_err(|e| QuilError::ExecutionUnavailable(format!("archive read: {e}")))?;
                // A whole frame is stored as whole and served onward, so its
                // body must be the one its header commits.
                let accepted = if !header_only
                    && !quil_engine::frame_validator::archive_global_body_authenticated(&frame)
                {
                    Err("served a request body that does not match its requests_root".to_string())
                } else {
                    self.anchor_accepted(number, &frame, &mut client).await
                };
                Ok::<_, QuilError>((frame, accepted))
            })
            .await
            .map_err(|_| QuilError::ExecutionUnavailable("timed out".into()))
            .and_then(|fetched| fetched);
            let frame = match fetched {
                Ok((frame, Ok(()))) => frame,
                Ok((_, Err(reason))) => {
                    refusals.push(format!("{addr}: {reason}"));
                    continue;
                }
                Err(error) => {
                    refusals.push(format!("{addr}: {error}"));
                    continue;
                }
            };
            self.clock_store.put_global_frame(&frame, None)?;
            self.anchor_warnings.lock().unwrap().recovered(number);
            info!(frame = number, archive = %addr, "recovered a worker's historical GLOBAL anchor from an archive");
            return Ok(frame);
        }
        let reason = if refusals.is_empty() {
            "no archive is known to ask".to_string()
        } else {
            refusals.join("; ")
        };
        if self
            .anchor_warnings
            .lock()
            .unwrap()
            .due(number, std::time::Instant::now())
        {
            warn!(frame = number, head, %reason, archives = refusals.len(),
                repeat_secs = ANCHOR_WARN_REPEAT.as_secs(), scope = "this node",
                action = "this node's workers cannot validate app frames anchored to it; retried on their next attempt; \
                    report it with this line if it persists",
                "historical GLOBAL anchor unavailable from archives");
        }
        Err(QuilError::ExecutionUnavailable(format!(
            "no archive served GLOBAL frame {number} ({reason})"
        )))
    }

    /// Why an archive's `frame` is not GLOBAL anchor `number`, if it is not.
    /// A valid frame without a certificate of its own is on the finalized
    /// chain only if a certified frame links down to it, as in the archive
    /// sync; a valid frame from a nullified view is not. So it is accepted
    /// when frames from the same archive, each valid and the child of the
    /// one below, reach a certified frame at most [`ANCHOR_DESCENT`] above.
    /// Those frames are only checked, never stored, so only their headers
    /// are fetched.
    async fn anchor_accepted(
        &self,
        number: u64,
        frame: &GlobalFrame,
        client: &mut quil_rpc::ArchiveClient,
    ) -> std::result::Result<(), String> {
        if frame.header.as_ref().map(|h| h.frame_number) != Some(number) {
            return Err("served another height".into());
        }
        if !(self.frame_validate)(frame) {
            return Err("failed the genesis-prover, VDF and signature check".into());
        }
        let mut below = std::borrow::Cow::Borrowed(frame);
        for above_number in number + 1..=number + ANCHOR_DESCENT {
            if super::archive_sync::frame_self_certified(&below, &self.verifier) {
                return Ok(());
            }
            let above = client.get_global_frame_header_only(above_number).await.map_err(|e| {
                format!("carries no certificate of its own, and frame {above_number} above it is unavailable: {e}")
            })?;
            let identity = below
                .header
                .as_ref()
                .and_then(|h| quil_crypto::poseidon::hash_bytes_to_32(&h.output).ok());
            let links = above.header.as_ref().is_some_and(|h| {
                h.frame_number == above_number
                    && identity.is_some_and(|id| h.parent_selector.as_slice() == id.as_slice())
            });
            if !links {
                return Err(format!("carries no certificate of its own, and frame {above_number} does not link down to it"));
            }
            if !(self.frame_validate)(&above) {
                return Err(format!(
                    "carries no certificate of its own, and frame {above_number} above it failed the genesis-prover, VDF and signature check"
                ));
            }
            below = std::borrow::Cow::Owned(above);
        }
        if super::archive_sync::frame_self_certified(&below, &self.verifier) {
            return Ok(());
        }
        Err(format!(
            "carries no certificate of its own, nor does a frame up to {} linking down to it",
            number + ANCHOR_DESCENT
        ))
    }

    /// A frame carrying a GLOBAL finalization certificate that verifies
    /// against the GLOBAL committee.
    fn self_certified(&self, frame: &GlobalFrame) -> bool {
        let Some(header) = frame.header.as_ref() else {
            return false;
        };
        let has_cert = header
            .public_key_signature_bls48581
            .as_ref()
            .and_then(|s| quil_cw_consensus::app_cert::unwrap_cert_from_header(&s.signature))
            .is_some();
        has_cert
            && self.verifier.knows_global_committee()
            && self.verifier.verify_global_finalization_cert(header)
    }

    /// The registry built from the prover tree committed by `header`.
    async fn registry_at(
        &self,
        scratch: &mut Scratch,
        header: &GlobalFrameHeader,
        root: [u8; 32],
    ) -> Result<Arc<quil_execution::InMemoryProverRegistry>> {
        if let Some((_, registry)) = scratch.registries.iter().find(|(r, _)| *r == root) {
            return Ok(registry.clone());
        }
        let removes: Option<[u8; 32]> = header
            .prover_tree_aux_roots
            .first()
            .and_then(|r| <[u8; 32]>::try_from(r.as_slice()).ok());
        // Without a committed removes root the phase must stay empty; a tree
        // left from an earlier pinned sync would mix states.
        if removes.is_none()
            && scratch
                .tree
                .as_ref()
                .is_some_and(|tree| tree.removes_synced)
        {
            scratch.tree = None;
        }
        if scratch.tree.is_none() {
            scratch.tree = Some(self.fresh_tree()?);
        }
        let tree = scratch.tree.as_mut().expect("created above");
        let removes_bytes = removes.map(|r| r.to_vec()).unwrap_or_default();
        let expected: [&[u8]; 4] = [&root, &removes_bytes, &[], &[]];
        let mut synced = false;
        for addr in self.pool.get_all().await {
            let attempt = async {
                let mut client = (self.connect)(addr.clone()).await?;
                crate::forest_sync::sync_shard_phases_on(
                    &mut client,
                    tree.crdt.clone(),
                    &[0xff; 32],
                    expected,
                    true,
                )
                .await
            };
            match attempt.await {
                Ok(Some(_)) => {
                    synced = true;
                    break;
                }
                Ok(None) => {}
                Err(error) => {
                    warn!(peer = %addr, %error, "historical committee: prover tree sync failed; trying the next archive")
                }
            }
        }
        if !synced {
            return Err(QuilError::ExecutionUnavailable(
                "no archive serves the prover tree at this root".into(),
            ));
        }
        tree.removes_synced |= removes.is_some();
        let store = quil_store::RocksHypergraphStore::new(tree.db.inner());
        let registry = tokio::task::spawn_blocking(move || {
            let mut registry = quil_execution::InMemoryProverRegistry::new();
            registry.refresh(&store)?;
            Ok::<_, QuilError>(registry)
        })
        .await
        .map_err(|e| QuilError::Internal(format!("historical registry task: {e}")))??;
        let registry = Arc::new(registry);
        scratch.registries.push_back((root, registry.clone()));
        while scratch.registries.len() > KEPT_REGISTRIES {
            scratch.registries.pop_front();
        }
        Ok(registry)
    }

    fn fresh_tree(&self) -> Result<ScratchTree> {
        if self.scratch_dir.exists() {
            std::fs::remove_dir_all(&self.scratch_dir).map_err(|e| {
                QuilError::Internal(format!("clear historical prover tree store: {e}"))
            })?;
        }
        let db =
            Arc::new(quil_store::RocksDb::open(&self.scratch_dir).map_err(|e| {
                QuilError::Internal(format!("open historical prover tree store: {e}"))
            })?);
        let crdt = super::worker_manager::build_thread_worker_hypergraph(
            &db,
            self.inclusion_prover.clone(),
            false,
        );
        Ok(ScratchTree {
            db,
            crdt,
            removes_synced: false,
        })
    }
}

/// A GLOBAL anchor source for this node's workers that resolves the service
/// when it is called: workers start before the archive sync has built it.
pub(crate) fn global_anchor_source(
    cell: Arc<std::sync::OnceLock<Arc<HistoricalCommittees>>>,
) -> quil_engine::global_anchor::GlobalAnchorSource {
    Arc::new(move |number: u64| {
        let service = cell.get().cloned();
        Box::pin(async move {
            match service {
                Some(service) => service.global_anchor(number).await,
                None => Err(QuilError::ExecutionUnavailable(
                    "GLOBAL anchor archive fallback not ready".into(),
                )),
            }
        })
            as std::pin::Pin<Box<dyn std::future::Future<Output = Result<GlobalFrame>> + Send>>
    })
}

/// The headers of the first `needed` frames of `run` (consecutive frames
/// ending in a certified one), each linked to the next by its parent
/// selector, so all are ancestors of the certified frame.
fn linked_headers(run: Vec<GlobalFrame>, needed: u64) -> Result<Vec<GlobalFrameHeader>> {
    let headers: Vec<GlobalFrameHeader> =
        run.into_iter().filter_map(|frame| frame.header).collect();
    for pair in headers.windows(2) {
        let identity = quil_crypto::poseidon::hash_bytes_to_32(&pair[0].output)?;
        if pair[1].frame_number != pair[0].frame_number + 1
            || pair[1].parent_selector.as_slice() != identity.as_slice()
        {
            return Err(QuilError::InvalidArgument(format!(
                "GLOBAL frame {} does not link to frame {}",
                pair[1].frame_number, pair[0].frame_number,
            )));
        }
    }
    Ok(headers.into_iter().take(needed as usize).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(number: u64, output: u8, parent: Option<u8>) -> GlobalFrameHeader {
        GlobalFrameHeader {
            frame_number: number,
            output: vec![output; 32],
            parent_selector: parent
                .map(|p| {
                    quil_crypto::poseidon::hash_bytes_to_32(&[p; 32])
                        .unwrap()
                        .to_vec()
                })
                .unwrap_or_default(),
            ..Default::default()
        }
    }

    fn frame(header: GlobalFrameHeader) -> GlobalFrame {
        GlobalFrame {
            header: Some(header),
            requests: vec![],
        }
    }

    struct NoFrames;
    impl quil_rpc::global_service::FrameLookup for NoFrames {
        fn get_latest_frame(&self) -> std::result::Result<GlobalFrame, String> {
            Err("no frames".into())
        }
        fn get_frame(&self, _: u64) -> std::result::Result<GlobalFrame, String> {
            Err("no frames".into())
        }
    }

    /// The committee a shard had around an anchor is rebuilt from the prover
    /// tree each GLOBAL header committed, synced from an archive at exactly
    /// that root: before a second prover joined, and after.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn committees_are_rebuilt_from_the_prover_trees_the_headers_commit() {
        use quil_types::crypto::Signer as _;
        let filter = vec![5u8; 33];
        let archive_dir = tempfile::tempdir().unwrap();
        let archive_db = Arc::new(quil_store::RocksDb::open(archive_dir.path()).unwrap());
        let archive = super::super::worker_manager::build_thread_worker_hypergraph(
            &archive_db,
            Arc::new(quil_tries::ShaInclusionProver),
            false,
        );
        let first = quil_crypto::FalconSigner::generate();
        let second = quil_crypto::FalconSigner::generate();
        quil_engine::genesis::seed_active_prover_on_filter(
            &archive,
            first.public_key(),
            100,
            10,
            &filter,
        )
        .unwrap();
        let (_, before) = archive.serve_forest_head(&[0xff; 32], 0).unwrap();
        quil_engine::genesis::seed_active_prover_on_filter(
            &archive,
            second.public_key(),
            100,
            14,
            &filter,
        )
        .unwrap();
        let (_, after) = archive.serve_forest_head(&[0xff; 32], 0).unwrap();
        assert_ne!(before, after);

        let server = quil_rpc::GlobalRpcServer::new(Arc::new(NoFrames)).with_forest_server(
            Arc::new(super::super::grpc::CrdtForestServer(archive.clone())),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let incoming =
            tonic::transport::server::TcpIncoming::from_listener(listener, true, None).unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    quil_types::proto::global::global_service_server::GlobalServiceServer::new(
                        server,
                    ),
                )
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });

        // Headers 14..=25 (anchors 15, 16): header 14 commits the tree after
        // frame 13 (only the first prover), the rest the tree after 14.
        let clock_dir = tempfile::tempdir().unwrap();
        let clock_db = quil_store::RocksDb::open(clock_dir.path()).unwrap();
        let clock = Arc::new(quil_store::RocksClockStore::new(clock_db.inner()));
        for n in 14..=25u64 {
            let root = if n <= 14 { before } else { after };
            let frame = GlobalFrame {
                header: Some(GlobalFrameHeader {
                    frame_number: n,
                    prover_tree_commitment: root.to_vec(),
                    ..Default::default()
                }),
                requests: vec![],
            };
            clock.put_global_frame(&frame, None).unwrap();
        }
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(
            std::time::Duration::from_secs(60),
        ));
        pool.add(addr).await;
        let scratch = tempfile::tempdir().unwrap();
        let verifier = Arc::new(quil_engine::frame_validator::GlobalFrameVerifier::with_bls(
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            Arc::new(quil_crypto::FalconKeyConstructor),
        ));
        let service = HistoricalCommittees::new(
            pool,
            Vec::new(),
            clock,
            Arc::new(|_| false),
            verifier,
            Arc::new(quil_tries::ShaInclusionProver),
            scratch.path().join("tree"),
        )
        .with_connector(Arc::new(|addr: String| {
            Box::pin(async move {
                quil_rpc::ArchiveClient::connect_plaintext(&addr)
                    .await
                    .map_err(|e| QuilError::ExecutionUnavailable(e.to_string()))
            })
        }));
        let committees = service.committees(&filter, 15).await.unwrap();
        let only_first = vec![first.public_key().to_vec()];
        assert!(
            committees.contains(&only_first),
            "the tree before the second join"
        );
        assert!(
            committees
                .iter()
                .any(|c| c.len() == 2 && c.contains(&second.public_key().to_vec())),
            "the tree after it: {} committees",
            committees.len(),
        );
        assert_eq!(committees.len(), 2);
        // Header 15 onward commit one tree, already kept from the first call.
        assert_eq!(service.committees(&filter, 16).await.unwrap().len(), 1);
        // A header the node does not hold must come from an archive, as a
        // validated, certified run; this one validates nothing.
        assert!(service.committees(&filter, 40).await.is_err());
    }

    /// Only a chain of consecutive frames, each naming the one below as its
    /// parent, is accepted up to the certified frame at its top.
    #[test]
    fn a_run_is_accepted_only_as_a_linked_chain() {
        let run = vec![
            frame(header(10, 1, None)),
            frame(header(11, 2, Some(1))),
            frame(header(12, 3, Some(2))),
        ];
        let headers = linked_headers(run, 2).unwrap();
        assert_eq!(
            headers.iter().map(|h| h.frame_number).collect::<Vec<_>>(),
            vec![10, 11]
        );

        let forged = vec![
            frame(header(10, 1, None)),
            frame(header(11, 2, Some(9))),
            frame(header(12, 3, Some(2))),
        ];
        assert!(
            linked_headers(forged, 2).is_err(),
            "a frame not linked to its parent"
        );
        let gap = vec![frame(header(10, 1, None)), frame(header(12, 3, Some(1)))];
        assert!(linked_headers(gap, 1).is_err(), "a skipped height");
    }

    const MINUTE: std::time::Duration = std::time::Duration::from_secs(60);

    /// A GLOBAL anchor no archive serves is warned about the first time and
    /// then once per repeat interval, each frame on its own; a recovered
    /// frame's next failure is new, and only a bounded set is remembered.
    #[test]
    fn anchor_failures_are_warned_once_per_interval_and_frame() {
        let start = std::time::Instant::now();
        let mut warnings = AnchorWarnings::default();
        assert!(warnings.due(5, start));
        assert!(!warnings.due(5, start + MINUTE * 29));
        assert!(warnings.due(6, start + MINUTE));
        assert!(warnings.due(5, start + MINUTE * 30));
        assert!(!warnings.due(5, start + MINUTE * 31));
        warnings.recovered(5);
        assert!(warnings.due(5, start + MINUTE * 32));
        for frame in 100..200 {
            warnings.due(frame, start + MINUTE * 33);
        }
        assert_eq!(warnings.warned.len(), ANCHOR_WARNED_KEPT);
        assert!(
            !warnings.due(199, start + MINUTE * 34),
            "the newest are kept"
        );
    }

    /// A GLOBAL frame from prover `[1; 32]` (the test's allowlist) or not,
    /// carrying a legacy aggregate signature or none.
    fn anchor(number: u64, allowed: bool, signed: bool) -> GlobalFrame {
        use quil_types::proto::keys::{Bls48581AggregateSignature, Bls48581g2PublicKey};
        GlobalFrame {
            header: Some(GlobalFrameHeader {
                frame_number: number,
                prover: vec![if allowed { 1 } else { 2 }; 32],
                public_key_signature_bls48581: signed.then(|| Bls48581AggregateSignature {
                    public_key: Some(Bls48581g2PublicKey {
                        key_value: vec![1; 8],
                    }),
                    signature: vec![2; 8],
                    bitmask: Vec::new(),
                }),
                ..Default::default()
            }),
            requests: vec![],
        }
    }

    /// Serves `anchor(n, true, true)` for every frame but 60 (unsigned, and 61
    /// does not link down to it), 70 (not from an allowed prover) and 80
    /// (another height).
    struct AnchorArchive;
    impl quil_rpc::global_service::FrameLookup for AnchorArchive {
        fn get_latest_frame(&self) -> std::result::Result<GlobalFrame, String> {
            Ok(anchor(200, true, true))
        }
        fn get_frame(&self, n: u64) -> std::result::Result<GlobalFrame, String> {
            Ok(match n {
                60 => anchor(60, true, false),
                70 => anchor(70, false, true),
                80 => anchor(81, true, true),
                n => anchor(n, true, true),
            })
        }
    }

    /// This node's anchor fetch from one plaintext archive serving `archive`,
    /// with GLOBAL frame 100 as this node's head; the guards keep the stores.
    async fn anchor_service<L: quil_rpc::global_service::FrameLookup + Send + Sync + 'static>(
        archive: L,
    ) -> (
        HistoricalCommittees,
        Arc<quil_store::RocksClockStore>,
        impl Sized,
    ) {
        let server = quil_rpc::GlobalRpcServer::new(Arc::new(archive));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let incoming =
            tonic::transport::server::TcpIncoming::from_listener(listener, true, None).unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    quil_types::proto::global::global_service_server::GlobalServiceServer::new(
                        server,
                    ),
                )
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        });
        let clock_dir = tempfile::tempdir().unwrap();
        let clock_db = quil_store::RocksDb::open(clock_dir.path()).unwrap();
        let clock = Arc::new(quil_store::RocksClockStore::new(clock_db.inner()));
        clock
            .put_global_frame(&anchor(100, true, true), None)
            .unwrap();
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(
            std::time::Duration::from_secs(60),
        ));
        pool.add(addr).await;
        let scratch = tempfile::tempdir().unwrap();
        let verifier = Arc::new(quil_engine::frame_validator::GlobalFrameVerifier::with_bls(
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            Arc::new(quil_crypto::FalconKeyConstructor),
        ));
        let service = HistoricalCommittees::new(
            pool,
            Vec::new(),
            clock.clone(),
            Arc::new(|frame: &GlobalFrame| {
                frame.header.as_ref().is_some_and(|h| h.prover == [1u8; 32])
            }),
            verifier,
            Arc::new(quil_tries::ShaInclusionProver),
            scratch.path().join("tree"),
        )
        .with_connector(Arc::new(|addr: String| {
            Box::pin(async move {
                quil_rpc::ArchiveClient::connect_plaintext(&addr)
                    .await
                    .map_err(|e| QuilError::ExecutionUnavailable(e.to_string()))
            })
        }));
        (service, clock, (clock_db, clock_dir, scratch))
    }

    /// A worker's GLOBAL anchor this node never held is fetched from an
    /// archive and stored only when it passes validation and is certified.
    /// Nothing at or above this node's head, nor the latest-frame alias, is
    /// fetched, and the head does not move.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn global_anchors_are_stored_only_validated_and_self_certified() {
        let (service, clock, _stores) = anchor_service(AnchorArchive).await;
        assert_eq!(
            service.global_anchor(50).await.unwrap(),
            anchor(50, true, true)
        );
        assert_eq!(clock.get_global_frame(50).unwrap(), anchor(50, true, true));
        for n in [60, 70, 80, 150, 0] {
            assert!(service.global_anchor(n).await.is_err(), "frame {n}");
            assert!(
                clock.get_global_frame(n).is_err(),
                "frame {n} is not stored"
            );
        }
        assert_eq!(
            service.global_anchor(100).await.unwrap(),
            anchor(100, true, true),
            "held frames are served"
        );
        assert_eq!(clock.get_latest_frame_number(), Some(100));
    }

    /// GLOBAL frame `n` from an allowed prover, the child of frame `n - 1`,
    /// with a legacy aggregate signature or none.
    fn linked(n: u64, signed: bool) -> GlobalFrame {
        let output = |n: u64| n.to_be_bytes().repeat(4);
        let mut frame = anchor(n, true, signed);
        let header = frame.header.as_mut().unwrap();
        header.output = output(n);
        header.parent_selector = quil_crypto::poseidon::hash_bytes_to_32(&output(n - 1))
            .unwrap()
            .to_vec();
        frame
    }

    /// Serves a chain of `linked` frames, signed except 20..=28, 30, 31 and
    /// 40; 31 is from a prover outside the allowlist.
    struct UncertifiedArchive;
    impl quil_rpc::global_service::FrameLookup for UncertifiedArchive {
        fn get_latest_frame(&self) -> std::result::Result<GlobalFrame, String> {
            Ok(linked(200, true))
        }
        fn get_frame(&self, n: u64) -> std::result::Result<GlobalFrame, String> {
            let mut frame = linked(n, !matches!(n, 20..=28 | 30 | 31 | 40));
            if n == 31 {
                frame.header.as_mut().unwrap().prover = vec![2; 32];
            }
            Ok(frame)
        }
    }

    /// An archive anchor without a certificate of its own is stored only when
    /// valid frames from the same archive, each the child of the one below,
    /// reach a certified frame at most `ANCHOR_DESCENT` above it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn uncertified_anchors_are_stored_only_below_a_linked_certified_frame() {
        let (service, clock, _stores) = anchor_service(UncertifiedArchive).await;
        assert_eq!(
            service.global_anchor(40).await.unwrap(),
            linked(40, false),
            "certified child"
        );
        assert_eq!(
            service.global_anchor(21).await.unwrap(),
            linked(21, false),
            "certified 8 frames above"
        );
        for n in [20, 30] {
            assert!(service.global_anchor(n).await.is_err(), "frame {n}");
            assert!(
                clock.get_global_frame(n).is_err(),
                "frame {n} is not stored"
            );
        }
        assert_eq!(clock.get_global_frame(40).unwrap(), linked(40, false));
        assert_eq!(clock.get_latest_frame_number(), Some(100));
    }

    /// Serves [`UncertifiedArchive`]'s chain with a request bundle in every
    /// frame, counting the frames read whole; a header is read alone.
    struct BundledArchive(Arc<std::sync::atomic::AtomicUsize>);
    impl quil_rpc::global_service::FrameLookup for BundledArchive {
        fn get_latest_frame(&self) -> std::result::Result<GlobalFrame, String> {
            UncertifiedArchive.get_latest_frame()
        }
        fn get_frame(&self, n: u64) -> std::result::Result<GlobalFrame, String> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut frame = UncertifiedArchive.get_frame(n)?;
            frame
                .requests
                .push(quil_types::proto::global::MessageBundle {
                    timestamp: n as i64,
                    ..Default::default()
                });
            Ok(frame)
        }
        fn get_frame_header(&self, n: u64) -> std::result::Result<GlobalFrameHeader, String> {
            UncertifiedArchive
                .get_frame(n)?
                .header
                .ok_or_else(|| "no header".to_string())
        }
    }

    /// Below this node's request-retention boundary an anchor is fetched as
    /// its header alone, as are the frames above it fetched to find its
    /// certificate, so the archive reads no request bundle. At or above the
    /// boundary the stored anchor counts as whole and keeps its bundles.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn anchors_below_the_retention_boundary_are_fetched_as_headers() {
        let whole = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let read_whole = || whole.load(std::sync::atomic::Ordering::SeqCst);
        let (service, clock, _stores) = anchor_service(BundledArchive(whole.clone())).await;
        assert_eq!(
            clock.prune_global_frame_requests(70).unwrap().retained_from,
            Some(30)
        );

        assert_eq!(
            service.global_anchor(21).await.unwrap(),
            linked(21, false),
            "certified 8 frames above"
        );
        assert_eq!(
            read_whole(),
            0,
            "the anchor and the 8 frames above it, as headers"
        );
        assert_eq!(clock.get_global_frame(21).unwrap(), linked(21, false));

        let anchor = service.global_anchor(40).await.unwrap();
        assert_eq!(
            anchor.requests.len(),
            1,
            "a whole frame at the boundary or above"
        );
        assert_eq!(anchor.header, linked(40, false).header);
        assert_eq!(read_whole(), 1, "its certified child, as a header");
        assert_eq!(clock.get_global_frame(40).unwrap(), anchor);
    }

    /// From the GLOBAL sync authentication frame on, an anchor read whole is
    /// stored only with the request body its header commits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_whole_anchor_whose_body_its_header_does_not_commit_is_not_stored() {
        // The test body runs on this thread; the anchor fetch is awaited here.
        quil_types::consensus::set_global_sync_authentication_frame_for_thread(Some(0));
        let whole = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (service, clock, _stores) = anchor_service(BundledArchive(whole)).await;
        let error = service.global_anchor(40).await.unwrap_err().to_string();
        quil_types::consensus::set_global_sync_authentication_frame_for_thread(None);
        assert!(error.contains("requests_root"), "{error}");
        assert!(clock.get_global_frame(40).is_err());
    }
}
