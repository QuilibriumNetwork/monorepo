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

/// Connects to an archive (`:8340` mTLS under the node's identity).
pub(crate) type ArchiveConnector = Arc<
    dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<quil_rpc::ArchiveClient>> + Send>>
        + Send
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
        }
    }

    #[cfg(test)]
    fn with_connector(mut self, connect: ArchiveConnector) -> Self {
        self.connect = connect;
        self
    }

    /// A source for app engines.
    pub(crate) fn source(self: &Arc<Self>) -> quil_engine::historical_committee::HistoricalCommitteeSource {
        let this = self.clone();
        Arc::new(move |filter: Vec<u8>, anchor: u64| {
            let this = this.clone();
            Box::pin(async move { this.committees(&filter, anchor).await })
                as std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<Vec<Vec<u8>>>>> + Send>>
        })
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
            let Ok(root) = <[u8; 32]>::try_from(header.prover_tree_commitment.as_slice()) else { continue };
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
            .map(|n| self.clock_store.get_global_frame(n).ok().and_then(|frame| frame.header))
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
        Err(last_error.unwrap_or_else(|| QuilError::ExecutionUnavailable("no archive to fetch GLOBAL headers from".into())))
    }

    /// Fetch frames from `lo` upward until one at or above `hi` carries its own
    /// certificate, then accept `lo..=hi` as its linked ancestors.
    async fn fetch_certified_run(&self, addr: &str, lo: u64, hi: u64) -> Result<Vec<GlobalFrameHeader>> {
        let mut client = (self.connect)(addr.to_string()).await?;
        let mut run: Vec<GlobalFrame> = Vec::new();
        for n in lo..=hi + MAX_RUN {
            let frame = match self.clock_store.get_global_frame(n) {
                Ok(frame) => frame,
                Err(_) => tokio::time::timeout(std::time::Duration::from_secs(30), client.get_global_frame(n))
                    .await
                    .map_err(|_| QuilError::ExecutionUnavailable(format!("GLOBAL frame {n} fetch timed out")))?
                    .map_err(|e| QuilError::ExecutionUnavailable(format!("GLOBAL frame {n}: {e}")))?,
            };
            if frame.header.as_ref().map(|h| h.frame_number) != Some(n) || !(self.frame_validate)(&frame) {
                return Err(QuilError::InvalidArgument(format!("GLOBAL frame {n} failed validation")));
            }
            let certified = n >= hi && self.self_certified(&frame);
            run.push(frame);
            if certified {
                return linked_headers(run, hi - lo + 1);
            }
        }
        Err(QuilError::ExecutionUnavailable("no certified GLOBAL frame above the needed headers".into()))
    }

    /// A frame carrying a GLOBAL finalization certificate that verifies
    /// against the GLOBAL committee.
    fn self_certified(&self, frame: &GlobalFrame) -> bool {
        let Some(header) = frame.header.as_ref() else { return false };
        let has_cert = header
            .public_key_signature_bls48581
            .as_ref()
            .and_then(|s| quil_cw_consensus::app_cert::unwrap_cert_from_header(&s.signature))
            .is_some();
        has_cert && self.verifier.knows_global_committee() && self.verifier.verify_global_finalization_cert(header)
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
        if removes.is_none() && scratch.tree.as_ref().is_some_and(|tree| tree.removes_synced) {
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
                crate::forest_sync::sync_shard_phases_on(&mut client, tree.crdt.clone(), &[0xff; 32], expected, true).await
            };
            match attempt.await {
                Ok(Some(_)) => {
                    synced = true;
                    break;
                }
                Ok(None) => {}
                Err(error) => warn!(peer = %addr, %error, "historical committee: prover tree sync failed; trying the next archive"),
            }
        }
        if !synced {
            return Err(QuilError::ExecutionUnavailable("no archive serves the prover tree at this root".into()));
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
            std::fs::remove_dir_all(&self.scratch_dir)
                .map_err(|e| QuilError::Internal(format!("clear historical prover tree store: {e}")))?;
        }
        let db = Arc::new(quil_store::RocksDb::open(&self.scratch_dir)
            .map_err(|e| QuilError::Internal(format!("open historical prover tree store: {e}")))?);
        let crdt = super::worker_manager::build_thread_worker_hypergraph(&db, self.inclusion_prover.clone(), false);
        Ok(ScratchTree { db, crdt, removes_synced: false })
    }
}

/// The headers of the first `needed` frames of `run` (consecutive frames
/// ending in a certified one), each linked to the next by its parent
/// selector, so all are ancestors of the certified frame.
fn linked_headers(run: Vec<GlobalFrame>, needed: u64) -> Result<Vec<GlobalFrameHeader>> {
    let headers: Vec<GlobalFrameHeader> = run.into_iter().filter_map(|frame| frame.header).collect();
    for pair in headers.windows(2) {
        let identity = quil_crypto::poseidon::hash_bytes_to_32(&pair[0].output)?;
        if pair[1].frame_number != pair[0].frame_number + 1 || pair[1].parent_selector.as_slice() != identity.as_slice() {
            return Err(QuilError::InvalidArgument(format!(
                "GLOBAL frame {} does not link to frame {}", pair[1].frame_number, pair[0].frame_number,
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
                .map(|p| quil_crypto::poseidon::hash_bytes_to_32(&[p; 32]).unwrap().to_vec())
                .unwrap_or_default(),
            ..Default::default()
        }
    }

    fn frame(header: GlobalFrameHeader) -> GlobalFrame {
        GlobalFrame { header: Some(header), requests: vec![] }
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
            &archive_db, Arc::new(quil_tries::ShaInclusionProver), false,
        );
        let first = quil_crypto::FalconSigner::generate();
        let second = quil_crypto::FalconSigner::generate();
        quil_engine::genesis::seed_active_prover_on_filter(&archive, first.public_key(), 100, 10, &filter).unwrap();
        let (_, before) = archive.serve_forest_head(&[0xff; 32], 0).unwrap();
        quil_engine::genesis::seed_active_prover_on_filter(&archive, second.public_key(), 100, 14, &filter).unwrap();
        let (_, after) = archive.serve_forest_head(&[0xff; 32], 0).unwrap();
        assert_ne!(before, after);

        let server = quil_rpc::GlobalRpcServer::new(Arc::new(NoFrames))
            .with_forest_server(Arc::new(super::super::grpc::CrdtForestServer(archive.clone())));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let incoming = tonic::transport::server::TcpIncoming::from_listener(listener, true, None).unwrap();
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(quil_types::proto::global::global_service_server::GlobalServiceServer::new(server))
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
                header: Some(GlobalFrameHeader { frame_number: n, prover_tree_commitment: root.to_vec(), ..Default::default() }),
                requests: vec![],
            };
            clock.put_global_frame(&frame, None).unwrap();
        }
        let pool = Arc::new(quil_rpc::ArchiveEndpointPool::new(std::time::Duration::from_secs(60)));
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
        assert!(committees.contains(&only_first), "the tree before the second join");
        assert!(
            committees.iter().any(|c| c.len() == 2 && c.contains(&second.public_key().to_vec())),
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
        let run = vec![frame(header(10, 1, None)), frame(header(11, 2, Some(1))), frame(header(12, 3, Some(2)))];
        let headers = linked_headers(run, 2).unwrap();
        assert_eq!(headers.iter().map(|h| h.frame_number).collect::<Vec<_>>(), vec![10, 11]);

        let forged = vec![frame(header(10, 1, None)), frame(header(11, 2, Some(9))), frame(header(12, 3, Some(2)))];
        assert!(linked_headers(forged, 2).is_err(), "a frame not linked to its parent");
        let gap = vec![frame(header(10, 1, None)), frame(header(12, 3, Some(1)))];
        assert!(linked_headers(gap, 1).is_err(), "a skipped height");
    }
}
