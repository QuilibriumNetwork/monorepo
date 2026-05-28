use std::sync::Arc;

use tracing::{debug, info, warn};

use quil_lifecycle::Supervisor;

pub(crate) struct GrpcArgs {
    pub config: quil_config::Config,
    pub network: u8,
    pub archive_mode: bool,
    pub db_arc: Arc<quil_store::RocksDb>,
    pub clock_store: Arc<quil_store::RocksClockStore>,
    pub hg_store: Arc<quil_store::RocksHypergraphStore>,
    pub message_collector: Arc<quil_engine::message_collector::MessageCollector>,
    pub current_frame: Arc<quil_engine::current_frame::CurrentFrame>,
    pub last_global_head_frame: Arc<std::sync::atomic::AtomicU64>,
    pub prover_address: [u8; 32],
    pub token_store: Arc<quil_store::RocksTokenStore>,
    pub prover_registry: Arc<quil_execution::SharedProverRegistry>,
    pub prover_pipeline: Arc<quil_engine::prover_pipeline::ProverPipeline>,
    pub worker_manager: Arc<dyn quil_engine::worker::WorkerManager>,
    pub inclusion_prover: Arc<dyn quil_types::crypto::InclusionProver>,
    pub peer_id: quil_p2p::PeerId,
    pub p2p_handle: quil_p2p::node::P2PHandle,
    pub file_key_manager: Arc<quil_keys::FileKeyManager>,
    pub mtls_seed: Option<[u8; 57]>,
    pub crdt: Arc<quil_hypergraph::HypergraphCrdt>,
    pub peer_info_cache: Arc<parking_lot::RwLock<
        std::collections::HashMap<Vec<u8>, quil_p2p::CanonicalPeerInfo>,
    >>,
    pub key_store: Arc<quil_store::RocksKeyStore>,
    pub metrics_handle: Option<metrics_exporter_prometheus::PrometheusHandle>,
    pub global_msg_tx: tokio::sync::broadcast::Sender<
        quil_types::proto::global::StreamGlobalMessagesResponse,
    >,
    pub archive_pool: Arc<quil_rpc::ArchiveEndpointPool>,
    pub spawner: quil_lifecycle::DetachedSpawner<anyhow::Error>,
}

pub(crate) fn spawn_all(
    sup: &mut Supervisor<anyhow::Error>,
    args: GrpcArgs,
) -> anyhow::Result<()> {
    let GrpcArgs {
        config,
        network,
        archive_mode,
        db_arc,
        clock_store,
        hg_store,
        message_collector,
        current_frame,
        last_global_head_frame,
        prover_address,
        token_store,
        prover_registry,
        prover_pipeline,
        worker_manager,
        inclusion_prover,
        peer_id,
        p2p_handle,
        file_key_manager,
        mtls_seed,
        crdt,
        peer_info_cache,
        key_store,
        metrics_handle,
        global_msg_tx,
        archive_pool,
        spawner,
    } = args;

    let grpc_addr = if config.listen_grpc_multiaddr.is_empty() {
        "0.0.0.0:8337".to_string()
    } else {
        let parts: Vec<&str> = config.listen_grpc_multiaddr
            .trim_start_matches('/')
            .split('/')
            .collect();
        if parts.len() >= 4 && parts[0] == "ip4" && parts[2] == "tcp" {
            format!("{}:{}", parts[1], parts[3])
        } else {
            "0.0.0.0:8337".to_string()
        }
    };

    // Bridge RocksClockStore to the FrameLookup trait
    struct ClockStoreFrameLookup(Arc<quil_store::RocksClockStore>);
    impl quil_rpc::FrameLookup for ClockStoreFrameLookup {
        fn get_latest_frame(&self) -> Result<quil_types::proto::global::GlobalFrame, String> {
            self.0.get_latest_global_frame().map_err(|e| e.to_string())
        }
        fn get_frame(&self, n: u64) -> Result<quil_types::proto::global::GlobalFrame, String> {
            self.0.get_global_frame(n).map_err(|e| e.to_string())
        }
    }
    // Submit handler
    let submit_mc = message_collector.clone();
    let submit_cf = current_frame.clone();
    let submit_handler: quil_rpc::SubmitHandler = Arc::new(
        move |request: tonic::Request<quil_types::proto::global::SubmitGlobalMessageRequest>| {
            let auth = request
                .extensions()
                .get::<quil_rpc::peer_auth_middleware::AuthenticatedPeer>()
                .cloned();
            let Some(auth) = auth else {
                quil_engine::metrics::inc_grpc_submits_rejected();
                return Err("unauthenticated peer — submit requires a valid Ed448 client cert".into());
            };
            let data = request.into_inner().data;
            if data.is_empty() {
                quil_engine::metrics::inc_grpc_submits_rejected();
                return Err("empty payload".into());
            }
            let rank = submit_cf.effective();
            let accepted = submit_mc.add_message(rank, data);
            if accepted {
                tracing::debug!(peer = %auth.peer_id, rank, "accepted gRPC submit");
                quil_engine::metrics::inc_grpc_submits_accepted();
                Ok(())
            } else {
                quil_engine::metrics::inc_grpc_submits_rejected();
                Err("message collector rejected".into())
            }
        },
    );
    let shards_store: Arc<dyn quil_types::store::ShardsStore> =
        Arc::new(quil_store::RocksShardsStore::new(db_arc.inner()));

    let global_worker_snap: quil_rpc::global_service::WorkerSnapshotFn = {
        let wm = worker_manager.clone();
        Arc::new(move || {
            quil_engine::worker::WorkerView::snapshot(wm.as_ref())
                .all
                .into_iter()
                .map(|w| quil_types::proto::global::GlobalGetWorkerInfoResponseItem {
                    core_id: w.core_id,
                    listen_multiaddr: String::new(),
                    stream_listen_multiaddr: String::new(),
                    filter: w.filter.clone(),
                    total_storage: w.total_storage,
                    allocated: !w.filter.is_empty(),
                })
                .collect()
        })
    };

    let global_shards_provider: quil_rpc::global_service::GlobalShardsProvider = {
        let store = hg_store.clone();
        let prover = inclusion_prover.clone();
        Arc::new(move |l1: &[u8; 3], l2: &[u8; 32]| {
            let shard = quil_types::store::ShardKey { l1: *l1, l2: *l2 };
            let phases = [
                ("vertex", "adds"),
                ("vertex", "removes"),
                ("hyperedge", "adds"),
                ("hyperedge", "removes"),
            ];
            let mut out: [(Vec<u8>, Vec<u8>, u64); 4] = [
                (vec![0u8; 64], Vec::new(), 0),
                (vec![0u8; 64], Vec::new(), 0),
                (vec![0u8; 64], Vec::new(), 0),
                (vec![0u8; 64], Vec::new(), 0),
            ];
            for (i, (set, phase)) in phases.iter().enumerate() {
                let Ok(Some(blob)) = store.load_tree_blob(set, phase, &shard) else {
                    continue;
                };
                let Ok(Some(root)) = quil_tries::deserialize_tree(&blob) else {
                    continue;
                };
                let mut tree = quil_tries::VectorCommitmentTree::new();
                tree.root = Some(root);
                tree.commit(prover.as_ref());
                if let Some(node) = tree.root.as_ref() {
                    match node {
                        quil_tries::VectorCommitmentNode::Branch(b) => {
                            out[i] = (b.commitment.clone(), b.size.to_signed_bytes_be(), b.leaf_count as u64);
                        }
                        quil_tries::VectorCommitmentNode::Leaf(l) => {
                            out[i] = (l.commitment.clone(), l.size.to_signed_bytes_be(), 1);
                        }
                    }
                }
            }
            out
        })
    };

    let app_shards_provider: quil_rpc::global_service::AppShardsProvider = {
        let crdt = crdt.clone();
        Arc::new(move |shard_key: &[u8], prefix: &[u32]| {
            let info = quil_types::store::ShardInfo {
                shard_key: shard_key.to_vec(),
                prefix: prefix.to_vec(),
                size: Vec::new(),
                data_shards: 0,
                commitment: Vec::new(),
            };
            let meta = quil_engine::app_shard_metadata::get_app_shard_metadata(crdt.as_ref(), &info)?;
            Some((meta.size, meta.data_shards, meta.commitments))
        })
    };

    let grpc_server = quil_rpc::GlobalRpcServer::new(
        Arc::new(ClockStoreFrameLookup(clock_store.clone())),
    )
    .with_submit_handler(submit_handler.clone())
    .with_shards_store(shards_store.clone())
    .with_worker_snapshot(global_worker_snap)
    .with_global_shards_provider(global_shards_provider)
    .with_app_shards_provider(app_shards_provider)
    .with_message_broadcast(global_msg_tx.clone());
    let hypersync = quil_rpc::hypersync_server::HyperSyncServer::new(hg_store.clone());

    let node_submit_mc = message_collector.clone();
    let node_submit_cf = current_frame.clone();
    let user_submit_handler: quil_rpc::node_service::UserSubmitHandler = Arc::new(
        move |data: Vec<u8>| -> Result<(), String> {
            if data.is_empty() {
                return Err("empty message".into());
            }
            let rank = node_submit_cf.effective();
            if node_submit_mc.add_message(rank, data) {
                Ok(())
            } else {
                Err("message collector rejected".into())
            }
        },
    );
    let mut node_rpc_builder = quil_rpc::NodeRpcServer::new()
        .with_peer_id(peer_id.to_string())
        .with_frame_counters(current_frame.clone(), last_global_head_frame.clone())
        .with_prover_address(prover_address.to_vec())
        .with_reachable(true)
        .with_token_store(token_store.clone() as Arc<dyn quil_types::store::TokenStore>)
        .with_prover_registry(prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>)
        .with_clock_store(clock_store.clone() as Arc<dyn quil_types::store::ClockStore>)
        .with_hypergraph_store(hg_store.clone() as Arc<dyn quil_types::store::HypergraphStore>)
        .with_submit_handler(user_submit_handler);
    if let Some(h) = metrics_handle.clone() {
        node_rpc_builder = node_rpc_builder.with_metrics_renderer(Arc::new(move || h.render()));
    }
    {
        let pic = peer_info_cache.clone();
        node_rpc_builder = node_rpc_builder.with_peer_info_snapshot(Arc::new(move || {
            pic.read().values().cloned().collect()
        }));
    }
    {
        let p2p_handle_for_score = p2p_handle.clone();
        let self_peer_id_for_score = p2p_handle.peer_id;
        node_rpc_builder = node_rpc_builder.with_peer_score_provider(Arc::new(move || {
            let h = p2p_handle_for_score.clone();
            let pid = self_peer_id_for_score;
            Box::pin(async move { h.get_peer_score(pid).await })
        }));
    }

    {
        let store = hg_store.clone();
        let prover_for_tp = inclusion_prover.clone();
        let gen: quil_rpc::TraversalProofGenerator = Arc::new(
            move |domain: [u8; 32], atom: String, phase: String, keys: Vec<Vec<u8>>| -> Result<Vec<u8>, String> {
                if keys.is_empty() {
                    return Err("keys must be non-empty".into());
                }
                let shard = quil_types::store::ShardKey {
                    l1: quil_hypergraph::addressing::get_bloom_filter_indices(&domain, 256, 3),
                    l2: domain,
                };
                let blob = store
                    .load_tree_blob(&atom, &phase, &shard)
                    .map_err(|e| format!("load_tree_blob: {e}"))?
                    .ok_or_else(|| "tree not found for domain".to_string())?;
                let root = quil_tries::deserialize_tree(&blob)
                    .map_err(|e| format!("deserialize: {e}"))?
                    .ok_or_else(|| "empty tree".to_string())?;
                let mut tree = quil_tries::VectorCommitmentTree::new();
                tree.root = Some(root);
                tree.commit(prover_for_tp.as_ref());
                let key_refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
                let proof = tree
                    .prove_multiple(prover_for_tp.as_ref(), &key_refs)
                    .ok_or_else(|| "no keys matched in tree".to_string())?;
                Ok(proof.to_bytes())
            },
        );
        node_rpc_builder = node_rpc_builder.with_traversal_proof_generator(gen);
    }

    let (peer_ed448_pub, peer_key_source): (Option<Vec<u8>>, &'static str) =
        match file_key_manager.get_signer_by_id("q-peer-key") {
            Ok(s) => (Some(s.public_key().to_vec()), "keystore q-peer-key"),
            Err(e) => {
                tracing::warn!(error = %e, "q-peer-key not loaded; Send will fall back to mtls_seed");
                match mtls_seed.as_ref() {
                    Some(seed) => (
                        Some(quil_p2p::ed448_identity::derive_public_key(seed)),
                        "config.p2p.peer_priv_key (mtls_seed)",
                    ),
                    None => (None, ""),
                }
            }
        };
    if let Some(peer_ed448_pub) = peer_ed448_pub {
        tracing::info!(
            pubkey_prefix = %hex::encode(&peer_ed448_pub[..peer_ed448_pub.len().min(8)]),
            pubkey_len = peer_ed448_pub.len(),
            source = peer_key_source,
            "Send authentication pubkey wired"
        );
        let send_p2p = p2p_handle.clone();
        let send_handler: quil_rpc::SendHandler = Arc::new(
            move |domain: Vec<u8>, payload: Vec<u8>, authentication: Vec<u8>|
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> {
                let p2p = send_p2p.clone();
                let ed448_pub = peer_ed448_pub.clone();
                Box::pin(async move {
                    if domain.len() != 32 {
                        return Err("domain must be 32 bytes".into());
                    }
                    if payload.is_empty() {
                        return Err("empty payload".into());
                    }
                    let mut digest = Vec::with_capacity(19 + 32 + payload.len());
                    digest.extend_from_slice(b"NODE_AUTHENTICATION");
                    digest.extend_from_slice(&domain);
                    digest.extend_from_slice(&payload);
                    let pk = ed448_rust::PublicKey::try_from(ed448_pub.as_slice())
                        .map_err(|e| format!("bad pubkey: {:?}", e))?;
                    if let Err(e) = pk.verify(&digest, &authentication, None) {
                        let head_n = payload.len().min(16);
                        let tail_n = payload.len().saturating_sub(16);
                        tracing::warn!(
                            pubkey = %hex::encode(&ed448_pub),
                            payload_len = payload.len(),
                            payload_head = %hex::encode(&payload[..head_n]),
                            payload_tail = %hex::encode(&payload[tail_n..]),
                            auth_len = authentication.len(),
                            auth_prefix = %hex::encode(&authentication[..authentication.len().min(8)]),
                            domain = %hex::encode(&domain),
                            error = ?e,
                            "Send Ed448 verify failed"
                        );
                        return Err(format!("authentication failed: {:?}", e));
                    }
                    let bitmask: Vec<u8> = if domain.iter().all(|&b| b == 0xff) {
                        quil_engine::bitmasks::GLOBAL_PROVER.to_vec()
                    } else {
                        quil_hypergraph::addressing::get_bloom_filter_indices(&domain, 256, 3).to_vec()
                    };
                    p2p.publish(bitmask, payload).await.map_err(|e| format!("p2p publish failed: {}", e))?;
                    Ok(())
                })
            },
        );
        node_rpc_builder = node_rpc_builder.with_send_handler_fn(send_handler);
    }
    struct WorkerControlBridge {
        worker_manager: Arc<dyn quil_engine::worker::WorkerManager>,
        prover_pipeline: Arc<quil_engine::prover_pipeline::ProverPipeline>,
        current_frame: Arc<quil_engine::current_frame::CurrentFrame>,
        spawner: quil_lifecycle::DetachedSpawner<anyhow::Error>,
    }
    impl quil_rpc::WorkerControl for WorkerControlBridge {
        fn set_manually_managed(&self, core_id: u32, manually_managed: bool) -> Result<(), String> {
            self.worker_manager.set_manually_managed(core_id, manually_managed).map_err(|e| e.to_string())
        }
        fn request_join<'a>(&'a self, filters: Vec<Vec<u8>>, worker_ids: Vec<u32>, _delegate: Vec<u8>)
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>
        {
            let pp = self.prover_pipeline.clone();
            let wm = self.worker_manager.clone();
            let frame = self.current_frame.effective();
            let join_spawner = self.spawner.clone();
            Box::pin(async move {
                if frame == 0 { return Err("no frames received yet".into()); }
                if filters.is_empty() { return Err("filters must be non-empty".into()); }
                if !worker_ids.is_empty() {
                    if worker_ids.len() != filters.len() {
                        return Err(format!("worker_ids length ({}) must match filters length ({})", worker_ids.len(), filters.len()));
                    }
                    for (filter, &core_id) in filters.iter().zip(worker_ids.iter()) {
                        wm.set_worker_filter(core_id, filter, false).map_err(|e| format!("pre-pin worker {core_id}: {e}"))?;
                        wm.set_pending_filter_frame(core_id, frame).map_err(|e| format!("set_pending_filter_frame {core_id}: {e}"))?;
                    }
                }
                let filters_for_task = filters.clone();
                let worker_ids_for_task = worker_ids.clone();
                join_spawner.detach("request-join-submit", async move {
                    if let Err(e) = pp.submit_join(filters_for_task, &worker_ids_for_task, frame).await {
                        tracing::warn!(error = %e, "request_join detached submit_join failed");
                    }
                    Ok(())
                });
                Ok(())
            })
        }
    }
    node_rpc_builder = node_rpc_builder.with_worker_control(Arc::new(WorkerControlBridge {
        worker_manager: worker_manager.clone(),
        prover_pipeline: prover_pipeline.clone(),
        current_frame: current_frame.clone(),
        spawner: spawner.clone(),
    }));

    let workers_view: Arc<std::sync::RwLock<Vec<quil_rpc::WorkerEntry>>> =
        Arc::new(std::sync::RwLock::new(Vec::new()));
    {
        let wm = worker_manager.clone();
        let view = workers_view.clone();
        sup.run_until_cancelled("workers-view-refresh", move |_token| async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
            loop {
                interval.tick().await;
                let entries: Vec<quil_rpc::WorkerEntry> =
                    quil_engine::worker::WorkerView::snapshot(wm.as_ref())
                        .all
                        .into_iter()
                        .map(|w| quil_rpc::WorkerEntry {
                            core_id: w.core_id,
                            filter: w.filter.clone(),
                            available_storage: w.available_storage,
                            total_storage: w.total_storage,
                            manually_managed: w.manually_managed,
                            allocated: !w.filter.is_empty(),
                        })
                        .collect();
                { *view.write().unwrap() = entries; }
            }
        });
    }
    node_rpc_builder = node_rpc_builder.with_workers_view(workers_view.clone());

    struct LocalShardInfoProvider {
        registry: Arc<dyn quil_types::consensus::ProverRegistry>,
        clock_store: Arc<dyn quil_types::store::ClockStore>,
        crdt: Arc<quil_hypergraph::HypergraphCrdt>,
        shards_store: Arc<dyn quil_types::store::ShardsStore>,
        self_address: Vec<u8>,
        current_frame: Arc<quil_engine::current_frame::CurrentFrame>,
        key_store: Arc<dyn quil_types::store::KeyStore>,
        peer_info_lookup: Arc<dyn Fn(&[u8]) -> Vec<String> + Send + Sync>,
        ed448_seed: Option<[u8; 57]>,
        archive_mode: bool,
        archive_pool: Arc<quil_rpc::ArchiveEndpointPool>,
    }
    impl quil_types::consensus::ShardInfoProvider for LocalShardInfoProvider {
        fn get_shard_info(&self, include_all: bool)
            -> quil_types::error::Result<(Vec<quil_types::consensus::ShardDetail>, u64, num_bigint::BigInt, u64)>
        {
            let cf = self.current_frame.effective();
            let (difficulty, frame_number) = match self.clock_store.get_latest_global_clock_frame() {
                Ok(frame) => {
                    let h = frame.header.unwrap_or_default();
                    (h.difficulty as u64, h.frame_number.max(cf))
                }
                Err(_) => (0u64, cf),
            };
            let provers = self.registry.get_provers(&self.self_address).unwrap_or_default();
            let allocated_filters: std::collections::HashSet<Vec<u8>> = provers
                .iter()
                .filter(|pr| pr.address == self.self_address)
                .flat_map(|pr| pr.allocations.iter().filter(|a| a.is_live(frame_number)).map(|a| a.confirmation_filter.clone()))
                .collect();
            let local_get_sizes = quil_engine::shard_info::local_app_shard_get_sizes(self.crdt.clone(), self.shards_store.clone());
            let local_result = quil_engine::shard_info::get_shard_info(
                include_all, &self.self_address, &allocated_filters, difficulty, frame_number,
                self.shards_store.as_ref(), self.registry.as_ref(), &local_get_sizes,
            );
            let expected_shards: usize = self.shards_store.range_app_shards()
                .map(|v| {
                    let mut keys: std::collections::HashSet<Vec<u8>> = std::collections::HashSet::new();
                    for s in v { keys.insert(s.shard_key); }
                    keys.len()
                })
                .unwrap_or(0);
            let local_incomplete = match &local_result {
                Ok((details, _diff, basis, _frame)) => {
                    let entries_below_shards = include_all && !self.archive_mode && details.len() < expected_shards;
                    basis.sign() == num_bigint::Sign::NoSign || entries_below_shards
                }
                Err(_) => true,
            };
            if !local_incomplete { return local_result; }
            let Some(seed) = self.ed448_seed else { return local_result; };

            use std::collections::HashMap;
            let key_store = self.key_store.clone();
            let peer_info_lookup = self.peer_info_lookup.clone();
            let clock_store = self.clock_store.clone();
            let shards_store = self.shards_store.clone();
            let archive_pool = self.archive_pool.clone();
            let prefetched: Result<HashMap<Vec<u8>, Vec<quil_types::proto::global::AppShardInfo>>, quil_types::error::QuilError> =
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async move {
                        let mut unique: HashMap<Vec<u8>, ()> = HashMap::new();
                        for s in shards_store.range_app_shards()? { unique.insert(s.shard_key, ()); }
                        let unique_keys: Vec<Vec<u8>> = unique.into_keys().collect();
                        let mut client_opt: Option<quil_rpc::ArchiveClient> = match clock_store.get_latest_global_clock_frame() {
                            Ok(frame) => match quil_rpc::peer_dial::dial_latest_frame_prover(&frame, key_store, move |peer_id| peer_info_lookup(peer_id), &seed).await {
                                Ok(c) => Some(c),
                                Err(e) => { tracing::debug!(error = %e, "shard info: dial_latest_frame_prover failed, will try archive pool"); None }
                            },
                            Err(e) => { tracing::debug!(error = %e, "shard info: no latest frame yet, will try archive pool"); None }
                        };
                        if client_opt.is_none() {
                            let endpoints = archive_pool.get_all().await;
                            for ep in &endpoints {
                                match quil_rpc::ArchiveClient::connect_mtls(ep, &seed).await {
                                    Ok(c) => { tracing::debug!(endpoint = %ep, "shard info: archive-pool fallback dial succeeded"); client_opt = Some(c); break; }
                                    Err(e) => { tracing::debug!(endpoint = %ep, error = %e, "shard info: archive-pool fallback dial failed"); }
                                }
                            }
                        }
                        let mut client = client_opt.ok_or_else(|| quil_types::error::QuilError::Internal("shard info: no archive endpoint reachable for fallback".into()))?;
                        tracing::debug!(unique_keys = unique_keys.len(), "shard info: about to fetch GetAppShards for unique parent keys");
                        let mut out: HashMap<Vec<u8>, Vec<quil_types::proto::global::AppShardInfo>> = HashMap::with_capacity(unique_keys.len());
                        for shard_key in unique_keys {
                            match client.get_app_shards(shard_key.clone(), Vec::new()).await {
                                Ok(infos) => { tracing::debug!(shard_key_hex = %hex::encode(&shard_key), infos = infos.len(), "shard info: GetAppShards returned"); out.insert(shard_key, infos); }
                                Err(e) => { tracing::debug!(error = %e, "remote shard info: get_app_shards failed for one shard"); }
                            }
                        }
                        tracing::debug!(keys = out.len(), "shard info: prefetched remote shard data");
                        Ok::<_, quil_types::error::QuilError>(out)
                    })
                });
            let prefetched = match prefetched {
                Ok(map) => map,
                Err(e) => { tracing::debug!(error = %e, "remote shard info fallback failed; returning local result"); return local_result; }
            };
            let prefetched = std::sync::Arc::new(prefetched);
            let remote_get_sizes = {
                let prefetched = prefetched.clone();
                move |shard_key: &[u8], shard_info: &quil_types::store::ShardInfo|
                    -> quil_types::error::Result<Vec<quil_engine::shard_info::ShardSizeEntry>>
                {
                    let infos = match prefetched.get(shard_key) { Some(v) => v.clone(), None => return Ok(Vec::new()), };
                    let mut out = Vec::with_capacity(infos.len().max(1));
                    if infos.is_empty() { return Ok(Vec::new()); }
                    for info in infos {
                        out.push(quil_engine::shard_info::ShardSizeEntry {
                            prefix: if info.prefix.is_empty() { shard_info.prefix.clone() } else { info.prefix },
                            size: info.size,
                            data_shards: info.data_shards,
                        });
                    }
                    Ok(out)
                }
            };
            quil_engine::shard_info::get_shard_info(
                include_all, &self.self_address, &allocated_filters, difficulty, frame_number,
                self.shards_store.as_ref(), self.registry.as_ref(), &remote_get_sizes,
            )
        }
    }
    let pic_for_lookup = peer_info_cache.clone();
    let peer_info_lookup: Arc<dyn Fn(&[u8]) -> Vec<String> + Send + Sync> =
        Arc::new(move |peer_id: &[u8]| -> Vec<String> {
            let map = pic_for_lookup.read();
            match map.get(peer_id) {
                Some(info) => info.reachability.first().map(|r| r.stream_multiaddrs.clone()).unwrap_or_default(),
                None => Vec::new(),
            }
        });
    node_rpc_builder = node_rpc_builder.with_shard_info_provider(Arc::new(LocalShardInfoProvider {
        registry: prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>,
        clock_store: clock_store.clone() as Arc<dyn quil_types::store::ClockStore>,
        crdt: crdt.clone(),
        shards_store: shards_store.clone(),
        self_address: prover_address.to_vec(),
        current_frame: current_frame.clone(),
        key_store: key_store.clone() as Arc<dyn quil_types::store::KeyStore>,
        peer_info_lookup,
        ed448_seed: mtls_seed,
        archive_mode,
        archive_pool: archive_pool.clone(),
    }));
    let node_rpc = node_rpc_builder;

    let stream_addr = {
        let parts: Vec<&str> = config.p2p.stream_listen_multiaddr.trim_start_matches('/').split('/').collect();
        if parts.len() >= 4 && parts[0] == "ip4" && parts[2] == "tcp" {
            format!("{}:{}", parts[1], parts[3])
        } else { "0.0.0.0:8340".to_string() }
    };

    if let Ok(addr) = grpc_addr.parse::<std::net::SocketAddr>() {
        let node_rpc_service = tonic::service::interceptor::InterceptedService::new(
            quil_types::proto::node::node_service_server::NodeServiceServer::new(node_rpc),
            quil_rpc::peer_auth_middleware::peer_auth_interceptor,
        );
        sup.spawn("node-grpc-server", move |node_grpc_token| async move {
            info!(addr = %addr, "starting NodeService gRPC (plaintext, qclient-facing)");
            tonic::transport::Server::builder()
                .add_service(node_rpc_service)
                .serve_with_shutdown(addr, async move { node_grpc_token.cancelled().await; })
                .await
                .map_err(anyhow::Error::from)
        });
    } else {
        warn!(addr = %grpc_addr, "invalid NodeService listen address, server disabled");
    }

    if let Ok(addr) = stream_addr.parse::<std::net::SocketAddr>() {
        let global_service = tonic::service::interceptor::InterceptedService::new(
            quil_types::proto::global::global_service_server::GlobalServiceServer::new(grpc_server),
            quil_rpc::peer_auth_middleware::peer_auth_interceptor,
        );
        let hypersync_service = tonic::service::interceptor::InterceptedService::new(
            quil_types::proto::application::hypergraph_comparison_service_server::HypergraphComparisonServiceServer::new(hypersync),
            quil_rpc::peer_auth_middleware::peer_auth_interceptor,
        );
        let app_shard_service = tonic::service::interceptor::InterceptedService::new(
            quil_types::proto::global::app_shard_service_server::AppShardServiceServer::new(
                quil_rpc::stub_services::AppShardRpcServer::new(clock_store.clone() as Arc<dyn quil_types::store::ClockStore>),
            ),
            quil_rpc::peer_auth_middleware::peer_auth_interceptor,
        );
        let key_registry_service = tonic::service::interceptor::InterceptedService::new(
            quil_types::proto::global::key_registry_service_server::KeyRegistryServiceServer::new(
                quil_rpc::stub_services::KeyRegistryRpcServer::new(prover_registry.clone() as Arc<dyn quil_types::consensus::ProverRegistry>),
            ),
            quil_rpc::peer_auth_middleware::peer_auth_interceptor,
        );
        let connectivity_service = tonic::service::interceptor::InterceptedService::new(
            quil_types::proto::node::connectivity_service_server::ConnectivityServiceServer::new(
                quil_rpc::stub_services::ConnectivityRpcServer,
            ),
            quil_rpc::peer_auth_middleware::peer_auth_interceptor,
        );

        let inbox_store = Arc::new(quil_store::RocksInboxStore::new(db_arc.inner()));
        let dispatch_service = tonic::service::interceptor::InterceptedService::new(
            quil_types::proto::global::dispatch_service_server::DispatchServiceServer::new(
                quil_rpc::dispatch_service::DispatchRpcServer::new(inbox_store.clone()),
            ),
            quil_rpc::peer_auth_middleware::peer_auth_interceptor,
        );

        let mixnet_service = tonic::service::interceptor::InterceptedService::new(
            quil_types::proto::global::mixnet_service_server::MixnetServiceServer::new(
                quil_rpc::mixnet_service::MixnetRpcServer::new(),
            ),
            quil_rpc::peer_auth_middleware::peer_auth_interceptor,
        );

        let pubsub_proxy_service = if config.engine.enable_master_proxy {
            let p2p_for_proxy = p2p_handle.clone();
            let peer_id_bytes: Vec<u8> = p2p_for_proxy.peer_id.to_bytes();
            let p2p_publish = p2p_for_proxy.clone();
            let p2p_sub = p2p_for_proxy.clone();
            let p2p_unsub = p2p_for_proxy.clone();
            let p2p_count = p2p_for_proxy.clone();
            let p2p_get_score = p2p_for_proxy.clone();
            let p2p_set_score = p2p_for_proxy.clone();
            let p2p_add_score = p2p_for_proxy.clone();
            let p2p_reconnect = p2p_for_proxy.clone();
            let p2p_bootstrap = p2p_for_proxy.clone();
            let p2p_discover = p2p_for_proxy.clone();
            let p2p_is_connected = p2p_for_proxy.clone();
            let sp_pub = spawner.clone();
            let sp_sub = spawner.clone();
            let sp_unsub = spawner.clone();
            let sp_set = spawner.clone();
            let sp_add = spawner.clone();
            let shim = quil_rpc::pubsub_proxy::P2pHandleShim {
                peer_id_bytes,
                publish: Arc::new(move |bitmask, data| {
                    let h = p2p_publish.clone();
                    sp_pub.detach("pubsub-proxy-publish", async move {
                        if let Err(e) = h.publish(bitmask, data).await {
                            warn!(error = %e, "pubsub-proxy publish failed");
                        }
                        Ok(())
                    });
                }),
                subscribe: Arc::new(move |bitmask| {
                    let h = p2p_sub.clone();
                    sp_sub.detach("pubsub-proxy-subscribe", async move {
                        h.subscribe(bitmask).await;
                        Ok(())
                    });
                }),
                unsubscribe: Arc::new(move |bitmask| {
                    let h = p2p_unsub.clone();
                    sp_unsub.detach("pubsub-proxy-unsubscribe", async move {
                        h.unsubscribe(bitmask).await;
                        Ok(())
                    });
                }),
                peer_count: Arc::new(move || p2p_count.peer_count()),
                get_peer_score: Arc::new(move |pid_bytes| {
                    let h = p2p_get_score.clone();
                    Box::pin(async move {
                        let peer = quil_p2p::PeerId::from_bytes(&pid_bytes).map_err(|e| format!("invalid peer id: {}", e))?;
                        Ok(h.get_peer_score(peer).await)
                    })
                }),
                set_peer_score: Arc::new(move |pid_bytes, score| {
                    let h = p2p_set_score.clone();
                    if let Ok(peer) = quil_p2p::PeerId::from_bytes(&pid_bytes) {
                        sp_set.detach("pubsub-proxy-set-score", async move {
                            h.set_peer_score(peer, score).await;
                            Ok(())
                        });
                    }
                }),
                add_peer_score: Arc::new(move |pid_bytes, delta| {
                    let h = p2p_add_score.clone();
                    if let Ok(peer) = quil_p2p::PeerId::from_bytes(&pid_bytes) {
                        sp_add.detach("pubsub-proxy-add-score", async move {
                            h.add_peer_score(peer, delta).await;
                            Ok(())
                        });
                    }
                }),
                reconnect: Arc::new(move |pid_bytes| {
                    let h = p2p_reconnect.clone();
                    Box::pin(async move {
                        let peer = quil_p2p::PeerId::from_bytes(&pid_bytes).map_err(|e| format!("invalid peer id: {}", e))?;
                        h.reconnect_peer(peer).await.map_err(|e| e.to_string())
                    })
                }),
                bootstrap: Arc::new(move || { let h = p2p_bootstrap.clone(); Box::pin(async move { h.bootstrap().await.map_err(|e| e.to_string()) }) }),
                discover_peers: Arc::new(move || { let h = p2p_discover.clone(); Box::pin(async move { h.discover_peers().await.map_err(|e| e.to_string()) }) }),
                is_peer_connected: Arc::new(move |_pid| p2p_is_connected.peer_count() > 0),
            };
            let ma_getter_handle = p2p_handle.clone();
            let own_multiaddrs: quil_rpc::pubsub_proxy::OwnMultiaddrsGetter =
                Arc::new(move || ma_getter_handle.observed_addresses());
            let peers_getter: quil_rpc::pubsub_proxy::PeerListGetter = Arc::new(|| Vec::new());
            let network = network as u32;
            let mut proxy_srv = quil_rpc::pubsub_proxy::PubSubProxyServer::new(
                shim, global_msg_tx.clone(), own_multiaddrs, peers_getter, network,
            );
            if let Some(seed) = mtls_seed {
                let pubkey = quil_p2p::ed448_identity::derive_public_key(&seed);
                let seed_for_sign = seed;
                let signer: quil_rpc::pubsub_proxy::Ed448Signer = Arc::new(move |msg: &[u8]| -> Result<Vec<u8>, String> {
                    let priv_key = ed448_rust::PrivateKey::from(seed_for_sign);
                    priv_key.sign(msg, None).map(|sig| sig.to_vec()).map_err(|e| format!("{:?}", e))
                });
                let pubkey_for_get = pubkey.clone();
                let pubkey_getter: quil_rpc::pubsub_proxy::Ed448PubkeyGetter = Arc::new(move || pubkey_for_get.clone());
                proxy_srv = proxy_srv.with_signer(signer).with_pubkey(pubkey_getter);
            }
            Some(tonic::service::interceptor::InterceptedService::new(
                quil_types::proto::proxy::pub_sub_proxy_server::PubSubProxyServer::new(proxy_srv),
                quil_rpc::peer_auth_middleware::peer_auth_interceptor,
            ))
        } else { None };

        let seed = mtls_seed.ok_or_else(|| anyhow::anyhow!(
            "peer gRPC requires an Ed448 identity — set `p2p.peerPrivKey` to a 57-byte hex seed (or 114-byte seed+pubkey). Without it no peer can authenticate against this node.",
        ))?;
        let tls_config = quil_rpc::build_quil_server_tls_config(&seed)
            .map_err(|e| anyhow::anyhow!("peer gRPC mTLS config init failed: {} — check `p2p.peerPrivKey`", e))?;
        sup.spawn("peer-grpc-server", move |peer_grpc_token| async move {
            info!(addr = %addr, "starting peer gRPC (mTLS)");
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(anyhow::Error::from)?;
            let tls_acceptor = tokio_rustls::TlsAcceptor::from(tls_config);
            let incoming = async_stream::stream! {
                loop {
                    let (tcp, _peer) = match listener.accept().await {
                        Ok(v) => v,
                        Err(e) => { warn!(error = %e, "peer gRPC accept failed"); continue; }
                    };
                    let acceptor = tls_acceptor.clone();
                    match acceptor.accept(tcp).await {
                        Ok(tls) => yield Ok::<_, std::io::Error>(tls),
                        Err(e) => { debug!(error = %e, "TLS handshake failed"); continue; }
                    }
                }
            };
            let mut builder = tonic::transport::Server::builder()
                .add_service(global_service)
                .add_service(hypersync_service)
                .add_service(app_shard_service)
                .add_service(key_registry_service)
                .add_service(connectivity_service)
                .add_service(dispatch_service)
                .add_service(mixnet_service);
            if let Some(pp) = pubsub_proxy_service {
                info!("registering PubSubProxy on peer gRPC listener");
                builder = builder.add_service(pp);
            }
            builder
                .serve_with_incoming_shutdown(incoming, async move { peer_grpc_token.cancelled().await; })
                .await
                .map_err(anyhow::Error::from)
        });
    } else {
        warn!(addr = %stream_addr, "invalid peer gRPC listen address, server disabled");
    }

    Ok(())
}
