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
    /// Peer→prover-key registry (KeyRegistry gossip), used to gate submit RPCs to
    /// ACTIVE provers (Go `authenticateProverFromContext`).
    pub signer_registry: Arc<quil_p2p::SignerRegistry>,
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
    /// Receive side of the direct global-consensus transport: peers'
    /// `SubmitGlobalConsensus` RPCs inject `(bitmask, data)` here, the
    /// same channel BlossomSub self-loopback uses, so the existing
    /// GLOBAL_FRAME / GLOBAL_CONSENSUS message-loop arms process them.
    pub consensus_loopback_tx:
        tokio::sync::mpsc::Sender<quil_p2p::node::ReceivedMessage>,
}

/// Serves forest-sync JMT nodes/values from the local CRDT's forest — the
/// server half of the efficient Merkle-diff sync ([`quil_forest::diff_leaves`]).
struct CrdtForestServer(Arc<quil_hypergraph::HypergraphCrdt>);

impl quil_rpc::global_service::ForestServer for CrdtForestServer {
    fn serve_node(&self, shard_id: &[u8], phase: u32, node_key: &[u8]) -> Option<Vec<u8>> {
        self.0.serve_forest_node(shard_id, phase as usize, node_key)
    }
    fn serve_value(
        &self,
        shard_id: &[u8],
        phase: u32,
        version: u64,
        key_hash: [u8; 32],
    ) -> Option<Vec<u8>> {
        self.0.serve_forest_value(shard_id, phase as usize, version, key_hash)
    }
    fn serve_head(&self, shard_id: &[u8], phase: u32) -> Option<(u64, [u8; 32])> {
        self.0.serve_forest_head(shard_id, phase as usize)
    }
    fn serve_preimage(&self, shard_id: &[u8], phase: u32, key_hash: [u8; 32]) -> Option<Vec<u8>> {
        self.0.serve_forest_preimage(shard_id, phase as usize, key_hash)
    }
    fn serve_vertex_blob(
        &self,
        shard_key: &[u8],
        phase: u32,
        id: &[u8],
        version: u64,
    ) -> Option<Vec<u8>> {
        if shard_key.len() < 35 {
            return None;
        }
        let shard = quil_types::store::ShardKey {
            l1: [shard_key[0], shard_key[1], shard_key[2]],
            l2: shard_key[3..35].try_into().ok()?,
        };
        self.0.serve_vertex_blob(&shard, phase as usize, id, version)
    }
    fn resolve_root(&self, shard_id: &[u8], phase: u32, root: [u8; 32]) -> Option<(u64, u64)> {
        self.0.resolve_root(shard_id, phase as usize, root)
    }
    fn serve_app_manifest(
        &self,
        app_address: &[u8],
        phase: u32,
        app_root: [u8; 32],
    ) -> Option<Vec<(Vec<u8>, [u8; 32], u64)>> {
        self.0.serve_app_manifest(app_address, phase as usize, app_root)
    }
}

/// Serves the lattice confidential-transaction wallet RPCs
/// (`GetCoinSpendWitness` / `ListDomainCoins`) by rebuilding a token domain's
/// coin accumulator from the live CRDT's committed coin vertices — the node-side
/// backing a wallet uses to build ring-CT spends (per-input membership witness)
/// and to enumerate/scan a domain's coins.
struct CrdtCoinWitness(
    Arc<quil_hypergraph::HypergraphCrdt>,
    Arc<dyn quil_types::store::ClockStore>,
);

impl quil_types::store::CoinWitnessProvider for CrdtCoinWitness {
    fn coin_spend_witnesses(
        &self,
        domain: &[u8],
        one_time_keys: &[Vec<u8>],
    ) -> quil_types::error::Result<(u32, Vec<u8>, Vec<quil_types::store::CoinWitnessData>)> {
        let state = quil_execution::hypergraph_state::HypergraphState::new(self.0.clone());
        let (depth, root, witnesses) =
            quil_execution::token_intrinsic::shadow_accumulator::coin_spend_witnesses(
                &state,
                domain,
                one_time_keys,
            )?;
        let out = witnesses
            .into_iter()
            .map(|w| quil_types::store::CoinWitnessData {
                one_time_key: w.one_time_key,
                found: w.found,
                leaf_index: w.leaf_index,
                auth_path: w.auth_path,
            })
            .collect();
        Ok((depth as u32, root, out))
    }

    fn list_domain_coins(
        &self,
        domain: &[u8],
    ) -> quil_types::error::Result<Vec<quil_types::store::DomainCoinData>> {
        let state = quil_execution::hypergraph_state::HypergraphState::new(self.0.clone());
        let coins = quil_execution::token_intrinsic::shadow_accumulator::scan_domain_coins(
            &state, domain,
        )?;
        Ok(coins
            .into_iter()
            .map(
                |(address, one_time_key, commitment, memo)| quil_types::store::DomainCoinData {
                    address,
                    one_time_key,
                    commitment,
                    memo,
                },
            )
            .collect())
    }

    fn list_domain_escrows(
        &self,
        domain: &[u8],
    ) -> quil_types::error::Result<Vec<quil_types::store::DomainEscrowData>> {
        let state = quil_execution::hypergraph_state::HypergraphState::new(self.0.clone());
        let escrows = quil_execution::token_intrinsic::shadow_accumulator::scan_domain_escrows(
            &state, domain,
        )?;
        Ok(escrows
            .into_iter()
            .map(|e| quil_types::store::DomainEscrowData {
                address: e.address,
                cv: e.cv,
                to_key: e.to_key,
                refund_key: e.refund_key,
                expiration: e.expiration,
                memo: e.memo,
            })
            .collect())
    }

    fn prover_reward_witness(
        &self,
        domain: &[u8],
        owner: &[u8],
    ) -> quil_types::error::Result<quil_types::store::RewardWitnessData> {
        use quil_hypergraph::addressing::{shard_key_for_location, Location};

        let is_quil = domain == quil_execution::domains::QUIL_TOKEN;
        // Reward vertex addressing (mirrors the engine's mint verify).
        let (prover_root_domain, leaf_owner) =
            quil_execution::token_intrinsic::mint::derive_pomw_addressing(domain, owner)?;
        let reward_domain: Vec<u8> = if is_quil {
            quil_execution::domains::GLOBAL.to_vec()
        } else {
            domain.to_vec()
        };

        let state = quil_execution::hypergraph_state::HypergraphState::new(self.0.clone());
        let va_disc = quil_execution::hypergraph_state::vertex_adds_discriminator()?;
        let blob = match state.get(&reward_domain, &leaf_owner, &va_disc)? {
            Some(b) => b,
            None => return Ok(quil_types::store::RewardWitnessData::default()),
        };
        // Claimable value = the reward vertex's Balance (low 16 bytes as u128).
        let tree = quil_execution::prover_registry::rebuild_vertex_tree_from_blob(&blob);
        let bal = quil_execution::global_intrinsic::materialize::read_reward_balance(&tree);
        let mut buf = [0u8; 16];
        if bal.len() >= 16 {
            buf.copy_from_slice(&bal[bal.len() - 16..]);
        } else {
            buf[16 - bal.len()..].copy_from_slice(&bal);
        }
        let value = u128::from_be_bytes(buf);
        if value == 0 {
            return Ok(quil_types::store::RewardWitnessData::default());
        }

        // Forest membership proof of the reward vertex against the committed root.
        let mut app = [0u8; 32];
        app.copy_from_slice(&prover_root_domain);
        let mut data = [0u8; 32];
        data.copy_from_slice(&leaf_owner);
        let shard = shard_key_for_location(&Location { app_address: app, data_address: data });
        let mut vertex_address = prover_root_domain.to_vec();
        vertex_address.extend_from_slice(&leaf_owner);
        let mp = self
            .0
            .build_membership_proof("vertex", "adds", &shard, &[(vertex_address, Vec::new())])?;
        let forest_proof = mp.to_bytes();

        // cited_frame = the latest committed global frame; its stored header
        // `prover_tree_commitment` is the reward root the engine resolves.
        let cited_frame = self
            .1
            .get_latest_global_clock_frame()
            .ok()
            .and_then(|f| f.header.map(|h| h.frame_number))
            .unwrap_or(0);

        Ok(quil_types::store::RewardWitnessData { found: true, forest_proof, value, cited_frame })
    }
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
        signer_registry,
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
        consensus_loopback_tx,
    } = args;

    // Prover authorizer (mirrors Go `authenticateProverFromContext`, used by
    // `GetGlobalProposal`): allow ONLY (a) THIS node's own identity — its
    // data-worker processes and pipeline, which dial with the node's own Ed448
    // seed and thus authenticate as this peer_id — or (b) a peer that resolves,
    // via its cross-signature-VERIFIED KeyRegistry binding, to an ACTIVE prover.
    // The `SignerRegistry` binds peer_id → the prover's FALCON consensus key (the
    // `bls_pubkey` field name is vestigial; it is verified with
    // `FalconKeyConstructor`); `prover_address_from_pubkey` = poseidon(key) is the
    // registry address. Unresolved / non-active ⇒ denied (strict, Go parity).
    #[allow(clippy::type_complexity)]
    let prover_authorizer: Arc<
        dyn Fn(&quil_rpc::peer_auth_middleware::AuthenticatedPeer) -> bool + Send + Sync,
    > = {
        let self_peer = peer_id.to_bytes();
        let sr = signer_registry.clone();
        let pr: Arc<dyn quil_types::consensus::ProverRegistry> = prover_registry.clone();
        Arc::new(move |auth| {
            let caller = auth.peer_id.to_bytes();
            if caller == self_peer {
                return true; // (a) the node's own workers/pipeline.
            }
            // (b) resolve peer_id → Falcon prover key → address → ACTIVE.
            let Some(prover_key) = sr.prover_key_for_peer_id(&caller) else {
                return false;
            };
            let Ok(addr) =
                quil_execution::global_intrinsic::materialize::prover_address_from_pubkey(
                    &prover_key,
                )
            else {
                return false;
            };
            matches!(
                pr.get_prover_info(&addr),
                Ok(Some(info))
                    if info.status == quil_types::consensus::ProverStatus::Active
                        || info
                            .allocations
                            .iter()
                            .any(|a| a.status == quil_types::consensus::ProverStatus::Active)
            )
        })
    };

    let grpc_addr = if config.listen_grpc_multiaddr.is_empty() {
        // SECURITY: default to LOCALHOST, not 0.0.0.0. This NodeService exposes
        // unauthenticated mutating RPCs (request_join, set_manually_managed, …) —
        // its per-RPC no-auth assumes a local/trusted caller (as in Go, where an
        // empty ListenGRPCMultiaddr leaves the server OFF). A world-open default
        // bind turns it into a remotely-reachable control plane. Operators who
        // need remote access set `listen_grpc_multiaddr` explicitly.
        "127.0.0.1:8337".to_string()
    } else {
        let parts: Vec<&str> = config.listen_grpc_multiaddr
            .trim_start_matches('/')
            .split('/')
            .collect();
        if parts.len() >= 4 && parts[0] == "ip4" && parts[2] == "tcp" {
            format!("{}:{}", parts[1], parts[3])
        } else {
            // SECURITY: default to LOCALHOST, not 0.0.0.0. This NodeService exposes
        // unauthenticated mutating RPCs (request_join, set_manually_managed, …) —
        // its per-RPC no-auth assumes a local/trusted caller (as in Go, where an
        // empty ListenGRPCMultiaddr leaves the server OFF). A world-open default
        // bind turns it into a remotely-reachable control plane. Operators who
        // need remote access set `listen_grpc_multiaddr` explicitly.
        "127.0.0.1:8337".to_string()
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
        /// Assemble the full proposal for frame `n` from the clock store, mirroring
        /// Go `GlobalConsensusEngine.GetGlobalProposal` (`services.go`): state + the
        /// parent's QC + the prior-rank TC (optional) + the proposer vote (keyed by
        /// `(filter, rank, frame-identity)`, where the frame identity is
        /// `poseidon(header.output)`).
        fn get_global_proposal(
            &self,
            n: u64,
        ) -> Result<quil_types::proto::global::GlobalProposal, String> {
            // Delegate to the shared, candidate-aware assembler so peers can
            // fetch an uncommitted TIP candidate over `GetGlobalProposal`.
            // Without the candidate fallback, a coordinated-halt tip (a frame
            // some replicas produced but never committed) is invisible to sync
            // and the chain can only be unstuck manually. See
            // `archive_sync::load_committed_or_tip_candidate`.
            super::archive_sync::reconstruct_local_proposal(self.0.as_ref(), n)
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
            // Presence-only, matching Go `SubmitGlobalMessage` (services.go:525):
            // any authenticated peer may submit; message CONTENT is prover-validated
            // downstream. (The self-OR-active-prover gate applies to
            // `GetGlobalProposal`, not the submit path.)
            let data = request.into_inner().data;
            if data.is_empty() {
                quil_engine::metrics::inc_grpc_submits_rejected();
                return Err("empty payload".into());
            }
            // Tag with the CONSENSUS RANK (not the frame number) — the
            // collector is keyed by rank and the leader collects via
            // `collect_for_rank(rank)`. Tagging with `effective()` (the
            // frame number, larger by the genesis offset) put messages
            // out of the collect range, so they never landed.
            let rank = submit_cf.effective_rank();
            match submit_mc.add_message_outcome(rank, data) {
                quil_engine::message_collector::SubmitOutcome::Accepted => {
                    tracing::debug!(peer = %auth.peer_id, rank, "accepted gRPC submit");
                    quil_engine::metrics::inc_grpc_submits_accepted();
                    Ok(())
                }
                // Already delivered (or superseded by a newer shard frame) —
                // the submitter's work is NOT lost, so report success. This is
                // what stops a prover's idempotent bundle re-submission from
                // being reported back to it as "message likely dropped" and
                // triggering a wasteful gossip-fallback + retry.
                quil_engine::message_collector::SubmitOutcome::Duplicate => {
                    quil_engine::metrics::inc_grpc_submits_duplicate();
                    Ok(())
                }
                quil_engine::message_collector::SubmitOutcome::Filtered => {
                    quil_engine::metrics::inc_grpc_submits_rejected();
                    tracing::warn!(
                        peer = %auth.peer_id,
                        rank,
                        "gRPC submit REJECTED by message collector (reason logged by collector: attestation / stale-shard-address / buffer-full / prover-only)"
                    );
                    Err("message collector rejected".into())
                }
            }
        },
    );
    // Direct global-consensus delivery handler. Peer archives call
    // `SubmitGlobalConsensus(bitmask, data)`; we inject it into the same
    // loopback channel the message loop reads, tagged with the original
    // topic, so the existing GLOBAL_FRAME / GLOBAL_CONSENSUS arms process
    // it exactly as they did for gossip. This is the receive half of
    // moving global consensus off gossip (app consensus is unaffected).
    let consensus_delivery: quil_rpc::global_service::ConsensusDeliveryHandler = {
        let tx = consensus_loopback_tx.clone();
        // Per-peer rate limit on direct :8340 consensus injection. Any Ed448-authed
        // peer (not just the committee) can call this; without a cap one peer can
        // force sustained downstream cert/signature verification. Generous vs the
        // real consensus cadence (a few vote/cert/block msgs per view).
        let cw_rate: Arc<std::sync::Mutex<std::collections::HashMap<Vec<u8>, (u64, u32)>>> =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        Arc::new(
            move |request: tonic::Request<quil_types::proto::global::SubmitGlobalConsensusRequest>| {
                let auth = request
                    .extensions()
                    .get::<quil_rpc::peer_auth_middleware::AuthenticatedPeer>()
                    .cloned();
                let Some(auth) = auth else {
                    return Err("unauthenticated peer — global consensus delivery requires a valid Ed448 client cert".into());
                };
                {
                    const MAX_CONSENSUS_MSGS_PER_SEC_PER_PEER: u32 = 256;
                    let now_s = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if let Ok(mut map) = cw_rate.lock() {
                        if map.len() > 4096 {
                            map.clear();
                        }
                        let e = map.entry(auth.peer_id.to_bytes()).or_insert((now_s, 0));
                        if e.0 == now_s {
                            e.1 = e.1.saturating_add(1);
                        } else {
                            *e = (now_s, 1);
                        }
                        if e.1 > MAX_CONSENSUS_MSGS_PER_SEC_PER_PEER {
                            return Err("global consensus delivery rate limited".into());
                        }
                    }
                }
                let req = request.into_inner();
                // Accept the two legacy global-consensus topics AND the
                // commonware-simplex CW channels (vote/cert/resolver/block), which
                // are also delivered point-to-point over this RPC.
                let is_cw = quil_engine::bitmasks::global_cw_channel_of(&req.bitmask).is_some();
                if !is_cw
                    && req.bitmask.as_slice() != quil_engine::bitmasks::GLOBAL_FRAME
                    && req.bitmask.as_slice() != quil_engine::bitmasks::GLOBAL_CONSENSUS
                {
                    return Err(format!(
                        "unexpected consensus bitmask 0x{}",
                        hex::encode(&req.bitmask)
                    ));
                }
                // DIAGNOSTIC: log every inbound consensus message at the RPC
                // boundary — peer, bitmask, size, and the peeked consensus type
                // — to pin why peer PROPOSALS never reach the vote path while
                // peer timeouts do. Remove once resolved.
                {
                    let tp = quil_engine::consensus_wire::peek_consensus_type(&req.data);
                    let tp_name = match tp {
                        Some(quil_engine::consensus_wire::GLOBAL_PROPOSAL_TYPE) => "proposal",
                        Some(quil_engine::consensus_wire::PROPOSAL_VOTE_TYPE) => "vote",
                        Some(quil_engine::consensus_wire::TIMEOUT_STATE_TYPE) => "timeout",
                        Some(_) => "other",
                        None => "unknown",
                    };
                    tracing::info!(
                        peer = %auth.peer_id,
                        bitmask = %hex::encode(&req.bitmask),
                        bytes = req.data.len(),
                        kind = tp_name,
                        "inbound SubmitGlobalConsensus",
                    );
                }
                let received = quil_p2p::node::ReceivedMessage {
                    bitmask: req.bitmask,
                    data: req.data,
                    from: auth.peer_id.to_bytes(),
                };
                match tx.try_send(received) {
                    Ok(()) => Ok(()),
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        Err("consensus receive queue full".into())
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        Err("consensus receive queue closed".into())
                    }
                }
            },
        )
    };

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

    // Wrap the clock-store lookup in a bounded read-through cache. The
    // peer-facing GlobalService serves frame/proposal reads to the whole
    // network; hundreds of nodes polling the same recent frames every
    // second would otherwise hit RocksDB (and re-assemble proposals) per
    // request. Frames are immutable by number so by-number caching is
    // always correct; the head is cached under a 1s TTL. 256 entries per
    // map keeps the hot tip + recent catch-up range resident.
    let cached_lookup = quil_rpc::global_service::CachingFrameLookup::new(
        ClockStoreFrameLookup(clock_store.clone()),
        256,
        std::time::Duration::from_secs(1),
    );
    let grpc_server = quil_rpc::GlobalRpcServer::new(
        Arc::new(cached_lookup),
    )
    .with_submit_handler(submit_handler.clone())
    .with_consensus_delivery(consensus_delivery)
    .with_shards_store(shards_store.clone())
    .with_worker_snapshot(global_worker_snap)
    .with_global_shards_provider(global_shards_provider)
    .with_app_shards_provider(app_shards_provider)
    .with_forest_server(Arc::new(CrdtForestServer(crdt.clone())))
    .with_message_broadcast(global_msg_tx.clone())
    // Gate worker-privileged RPCs (StreamGlobalMessages, GetWorkerInfo) to this
    // node's OWN identity: only our data-worker processes — which dial with the
    // node's Ed448 seed and thus authenticate as this same peer_id — may invoke
    // them. A remote machine handshakes as a different peer_id and is denied.
    .with_self_peer_id(peer_id.to_bytes())
    // GetGlobalProposal: self OR an active prover (Go authenticateProverFromContext).
    .with_prover_authorizer(prover_authorizer.clone());
    // (The legacy KZG HyperSync serve side + its dedicated runtime were removed
    // with the forest-sync cutover — forest sync serves via GlobalService's
    // GetForest* RPCs, and the KZG PerformSync stream had no remaining clients.)

    // Dedicated runtime for Ed448 TLS handshakes. Handshake tasks used to be
    // spawned onto the peer-gRPC runtime itself, so a connect storm (e.g.
    // every prover reconnecting the moment frames start moving again after a
    // halt) ran an UNBOUNDED number of concurrent Ed448 handshakes — heavy
    // CPU work — on the same 8 workers that carry latency-critical
    // archive↔archive consensus delivery (SubmitGlobalConsensus votes /
    // proposals). Isolating the handshake crypto here keeps a hammer of new
    // connections from delaying vote delivery; completed connections are
    // handed back to the peer-gRPC runtime for h2/RPC serving as before.
    // Leaked for the same reason as `hypersync_rt`.
    let tls_handshake_rt: &'static tokio::runtime::Runtime = Box::leak(Box::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("tls-handshake")
            .enable_all()
            .build()?,
    ));

    let node_submit_mc = message_collector.clone();
    let node_submit_cf = current_frame.clone();
    let user_submit_handler: quil_rpc::node_service::UserSubmitHandler = Arc::new(
        move |data: Vec<u8>| -> Result<(), String> {
            if data.is_empty() {
                return Err("empty message".into());
            }
            // Consensus rank, not frame number (see peer submit handler).
            let rank = node_submit_cf.effective_rank();
            match node_submit_mc.add_message_outcome(rank, data) {
                // Duplicate = already delivered → success (not a drop).
                quil_engine::message_collector::SubmitOutcome::Accepted
                | quil_engine::message_collector::SubmitOutcome::Duplicate => Ok(()),
                quil_engine::message_collector::SubmitOutcome::Filtered => {
                    Err("message collector rejected".into())
                }
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
        .with_coin_witness_provider(Arc::new(CrdtCoinWitness(
            crdt.clone(),
            clock_store.clone() as Arc<dyn quil_types::store::ClockStore>,
        )))
        .with_submit_handler(user_submit_handler);
    if let Some(h) = metrics_handle.clone() {
        // Unified exposition: the facade recorder's snapshot plus the p2p
        // `prometheus-client` families (blossomsub_* / libp2p_*, registered
        // via set_extra_metrics_render once networking is up).
        node_rpc_builder = node_rpc_builder.with_metrics_renderer(Arc::new(move || {
            let mut out = h.render();
            let extra = crate::rpc_metrics::extra_metrics_render();
            if !extra.is_empty() {
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(&extra);
            }
            out
        }));
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
        let crdt_for_tp = crdt.clone();
        let gen: quil_rpc::TraversalProofGenerator = Arc::new(
            move |domain: [u8; 32], atom: String, phase: String, keys: Vec<Vec<u8>>| -> Result<Vec<u8>, String> {
                if keys.is_empty() {
                    return Err("keys must be non-empty".into());
                }
                let shard = quil_types::store::ShardKey {
                    l1: quil_hypergraph::addressing::get_bloom_filter_indices(&domain, 256, 3),
                    l2: domain,
                };
                // Forest cutover: on a migrated node produce a
                // `quil_forest::MembershipProof` (per-field JMT inclusion
                // proofs) instead of the KZG multiproof. Each request key is
                // `data_address(32) ‖ field_key`; the vertex's L3 id is
                // `domain ‖ data_address` (`Location::to_id`), and keys sharing
                // a data_address are grouped into one vertex proof.
                if crdt_for_tp.has_forest() {
                    let mut groups: Vec<(Vec<u8>, Vec<Vec<u8>>)> = Vec::new();
                    for k in &keys {
                        if k.len() <= 32 {
                            return Err(format!(
                                "forest proof key must be data_address(32) ‖ field_key, got {} bytes",
                                k.len()
                            ));
                        }
                        let mut vertex_id = Vec::with_capacity(64);
                        vertex_id.extend_from_slice(&domain);
                        vertex_id.extend_from_slice(&k[..32]);
                        let field_key = k[32..].to_vec();
                        match groups.iter_mut().find(|(a, _)| *a == vertex_id) {
                            Some((_, fields)) => fields.push(field_key),
                            None => groups.push((vertex_id, vec![field_key])),
                        }
                    }
                    let mp = crdt_for_tp
                        .build_membership_proof(&atom, &phase, &shard, &groups)
                        .map_err(|e| format!("build_membership_proof: {e}"))?;
                    return Ok(mp.to_bytes());
                }
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
        // Reuse the prover pipeline's transport for GLOBAL_PROVER-domain
        // sends. The transport already implements the correct fan-out:
        // gRPC to every known archive (so non-archive nodes have a
        // delivery path) plus optional BlossomSub publish on archive
        // nodes. A direct `p2p.publish(GLOBAL_PROVER, ...)` on a
        // non-archive node fails — the node is not subscribed to that
        // bitmask, so BlossomSub returns "not subscribed". This was the
        // observed failure in the client prover-manage TUI: the Send
        // RPC reached a non-archive node, which tried a raw BlossomSub
        // publish and bounced.
        let send_transport = prover_pipeline.transport.clone();
        let send_handler: quil_rpc::SendHandler = Arc::new(
            move |domain: Vec<u8>, payload: Vec<u8>, authentication: Vec<u8>|
            -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>> {
                let p2p = send_p2p.clone();
                let transport = send_transport.clone();
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
                    if domain.iter().all(|&b| b == 0xff) {
                        // Global-prover-domain bundle (Join / Leave /
                        // Confirm / Resume / Reject / AltShard /
                        // Delegate). Route through the transport so a
                        // non-archive node still reaches the network
                        // via the archive gRPC fan-out.
                        transport
                            .publish_prover_bundle(payload)
                            .await
                            .map_err(|e| format!("prover transport publish failed: {}", e))?;
                    } else {
                        // Shard-domain message (token / app intrinsic).
                        // Route via the shard's bloom-filter bitmask;
                        // the local node is expected to be subscribed
                        // there if it's participating in that shard.
                        let bitmask = quil_hypergraph::addressing::get_bloom_filter_indices(
                            &domain, 256, 3,
                        )
                        .to_vec();
                        p2p.publish(bitmask, payload)
                            .await
                            .map_err(|e| format!("p2p publish failed: {}", e))?;
                    }
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
        // The node's FALCON q-prover-key (1281 B) — the `:8340` PQNoise transport
        // identity for the outbound shard-info dial. `ed448_seed` is the legacy
        // Ed448 mTLS seed (57 B), kept only as a last-resort fallback: handing it
        // to the Falcon transport fails to decode ("falcon feature not enabled").
        falcon_signing_key: Option<Vec<u8>>,
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
            // The :8340 transport decodes a FALCON signing key on both ends, so the
            // outbound dial MUST present the node's Falcon q-prover-key (1281 B),
            // NOT the legacy Ed448 seed (57 B) — the latter fails to decode as
            // Falcon and the dial dies with "falcon keypair: ... feature not
            // enabled". Fall back to the Ed448 seed only if the Falcon key is
            // unavailable, matching the server side.
            let Some(seed) = self
                .falcon_signing_key
                .clone()
                .or_else(|| self.ed448_seed.map(|s| s.to_vec()))
            else {
                return local_result;
            };

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
        // Falcon transport identity for the outbound shard-info dial (gated by a
        // transport identity being present, same as the onion dialer / server).
        falcon_signing_key: if mtls_seed.is_some() {
            file_key_manager.get_secret_key_bytes_by_id("q-prover-key").ok()
        } else {
            None
        },
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
                // h2 PING-based reaping of dead clients. Without it a
                // peer that vanishes without FIN holds its fd forever
                // and the fd count grows monotonically.
                .http2_keepalive_interval(Some(std::time::Duration::from_secs(20)))
                .http2_keepalive_timeout(Some(std::time::Duration::from_secs(10)))
                .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
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
            // 64 MiB decode/encode (tonic defaults to 4 MiB). Inbound
            // submits are small, but full global-frame / app-shard
            // responses this server encodes can exceed 4 MiB; the default
            // truncated them, surfacing as `h2 protocol error: error
            // reading a body` on the client. Mirrors the client limits.
            quil_types::proto::global::global_service_server::GlobalServiceServer::new(grpc_server)
                .max_decoding_message_size(64 * 1024 * 1024)
                .max_encoding_message_size(64 * 1024 * 1024),
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
        // Construct permissive (`responsible_filters = None` => responsible
        // for ALL filters). This keeps external dispatch working while the
        // responsibility guard is PRESENT and ENFORCED-when-set. Archives
        // legitimately store all filters, so they stay `None`.
        //
        // TODO(non-archive coverage): a non-archive node should only accept
        // dispatch puts/gets for the shards it actually covers. Once the
        // lifecycle cleanly exposes its live covered-shard set, call
        // `dispatch.set_responsible_filters(Some(covered_shard_bloom_filters))`
        // (3-byte `get_bloom_filter_indices(addr,256,3)` filters) to enforce
        // it. Archives must remain `None` (store all). Getting this set
        // wrong (empty/stale) would reject-all and break messaging
        // network-wide, so we default permissive rather than Go's reject-all.
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

        // Onion routing link-layer transport (OnionService.Connect). Mirrors Go
        // `RegisterOnionServiceServer(server, e.onionService)`: a peer that
        // advertises the routing capability can open a bidi cell stream through
        // us. Routing eligibility = peer is in the PeerInfo cache AND advertises
        // `PROTOCOL_ROUTING`; the lookup returns its stream multiaddrs (as Go's
        // `validatePeer` + `ConnectToPeer` do). The circuit crypto is the PQ
        // sntrup761 KEM + AES-GCM stack in `quil_p2p::onion`.
        let pic_for_onion = peer_info_cache.clone();
        let onion_peer_lookup: quil_rpc::onion_service::PeerRoutingLookup =
            Arc::new(move |peer_id: &[u8]| {
                let map = pic_for_onion.read();
                let info = map.get(peer_id)?;
                let has_routing = info.capabilities.iter().any(|c| {
                    c.protocol_identifier == quil_rpc::onion_service::PROTOCOL_ROUTING
                });
                if !has_routing {
                    return None;
                }
                Some(
                    info.reachability
                        .first()
                        .map(|r| r.stream_multiaddrs.clone())
                        .unwrap_or_default(),
                )
            });
        // With the node's ed448 seed the transport gains an OUTBOUND dialer
        // (`ensure_connected` opens pqnoise client streams to peers), so this node
        // can proactively build circuits and forward to hops that haven't dialed
        // it. Without a seed it's server-only (relays/replies for inbound diallers).
        // Onion dialer identity = the Falcon network key (present iff this node
        // has a transport identity, gated by mtls_seed presence as before).
        let onion_dialer_falcon: Option<Vec<u8>> = if mtls_seed.is_some() {
            file_key_manager.get_secret_key_bytes_by_id("q-prover-key").ok()
        } else {
            None
        };
        let onion_transport = match onion_dialer_falcon.clone() {
            Some(sk) => quil_rpc::onion_service::OnionTransport::new_with_dialer(
                peer_id.to_bytes(),
                onion_peer_lookup.clone(),
                sk,
            ),
            None => quil_rpc::onion_service::OnionTransport::new(
                peer_id.to_bytes(),
                onion_peer_lookup.clone(),
            ),
        };

        // Activate the unified onion node: install the CREATE/forward/EXTEND/
        // backward dispatcher on the transport, keyed by this node's sntrup761
        // `q-onion-key` secret so it can decapsulate CREATE cells. This turns the
        // node into a live PQ onion relay (and exit) for peers that build circuits
        // through it. `OnionNode` shares the transport's inner state, so the
        // dispatcher and the served `OnionService` operate on the same streams.
        // The node handle is intentionally not retained: the dispatcher closure it
        // installs owns its own relay/originator Arcs, so relaying continues for
        // the transport's lifetime; a handle is only needed once this node also
        // *originates* circuits (no such driver yet).
        // On by default; `p2p.disableOnionRouting: true` turns the relay off (the
        // transport is still served, but no dispatcher runs and the routing
        // capability is not advertised, so no circuits traverse this node).
        if config.p2p.disable_onion_routing {
            info!("onion routing disabled by config (p2p.disableOnionRouting)");
        } else {
            match file_key_manager.get_secret_key_bytes_by_id("q-onion-key") {
                Ok(onion_secret) => {
                    let onion_dyn: Arc<dyn quil_p2p::onion::Transport> =
                        Arc::new(onion_transport.clone());
                    // DEFENSE: next-hop / endpoint validator — a peer is a valid
                    // onion hop only if it's in the PeerInfo cache AND advertises
                    // PROTOCOL_ROUTING. Circuits therefore stay inside the network;
                    // an open-web address is never a hop. (Self-connection is
                    // rejected separately by OnionNode + the transport.)
                    let pic_for_validator = peer_info_cache.clone();
                    let onion_peer_validator: quil_p2p::onion::PeerValidator =
                        Arc::new(move |peer_id: &[u8]| {
                            let map = pic_for_validator.read();
                            map.get(peer_id).is_some_and(|info| {
                                info.capabilities.iter().any(|c| {
                                    c.protocol_identifier
                                        == quil_rpc::onion_service::PROTOCOL_ROUTING
                                })
                            })
                        });
                    // Exit consumer: when a circuit terminates here, proxy its
                    // payload to another peer's gRPC and relay the response back.
                    // AUTHORIZATION allow-list — only these methods may be reached
                    // through the tunnel (anonymous circuit traffic must not be able
                    // to hit consensus submits, self-gated, or streaming RPCs). The
                    // target peer still applies its own per-caller auth to this
                    // exit's authenticated pqnoise identity. Needs the ed448 seed to
                    // dial; without it we fall back to log-and-drop.
                    let (exit_handler, exit_proxy): (quil_p2p::onion::OnData, _) = match onion_dialer_falcon.clone() {
                        Some(seed) => {
                            let allowed: std::collections::HashSet<String> = [
                                "/quilibrium.node.global.pb.DispatchService/PutInboxMessage",
                                "/quilibrium.node.global.pb.DispatchService/GetInboxMessages",
                                "/quilibrium.node.global.pb.GlobalService/GetGlobalFrame",
                                "/quilibrium.node.global.pb.GlobalService/GetAppShards",
                            ]
                            .iter()
                            .map(|s| s.to_string())
                            .collect();
                            let proxy = quil_rpc::onion_exit::OnionExitProxy::new(
                                seed,
                                onion_peer_lookup.clone(),
                                allowed,
                            );
                            (proxy.clone().into_on_data(), Some(proxy))
                        }
                        None => {
                            let h: quil_p2p::onion::OnData =
                                Arc::new(|_up_peer: &[u8], circ_id, payload: Vec<u8>| {
                                    debug!(circ_id, bytes = payload.len(), "onion exit: no dialer seed; dropping");
                                });
                            (h, None)
                        }
                    };
                    let onion_node = quil_p2p::onion::node::OnionNode::new(
                        onion_dyn,
                        peer_id.to_bytes(),
                        Some(onion_secret),
                        Some(onion_peer_validator),
                        Some(exit_handler),
                        None,
                    );
                    // Give the exit proxy a reply handle (self-sufficient: it holds
                    // the relay + transport Arcs, so the node itself may be dropped).
                    if let Some(proxy) = exit_proxy {
                        proxy.set_reply_handle(onion_node.reply_handle());
                    }
                    let _ = onion_node;
                    info!("onion routing active: node is a live PQ onion relay + RPC-proxy exit");
                }
                Err(e) => {
                    warn!(error = %e, "q-onion-key unavailable; onion relay dispatcher disabled (transport still served)");
                }
            }
        }

        let onion_service = tonic::service::interceptor::InterceptedService::new(
            quil_types::proto::global::onion_service_server::OnionServiceServer::new(
                onion_transport,
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
        sup.spawn("peer-grpc-server", move |peer_grpc_token| async move {
            // The peer-facing gRPC server (:8340) runs on its OWN dedicated
            // multi-threaded runtime. The main runtime carries consensus,
            // commit (which holds the CRDT write lock across KZG+I/O),
            // materialization and frame production — bursts of that heavy,
            // .await-free work saturate every main-runtime worker and starve
            // this network-facing path: field captures showed get_global_frame
            // (a single frame read) AND even the Ed448 TLS handshake timing
            // out at 10-15s while the node was busy, which blocked prover
            // submission and archive↔archive sync network-wide. Isolating the
            // accept loop / handshakes / RPC handlers onto separate worker
            // threads keeps :8340 responsive regardless of main-runtime load.
            //
            // Driven via spawn_blocking so (a) we don't pin a main-runtime
            // async worker for the server's whole lifetime and (b) dropping
            // the dedicated runtime happens in a blocking context (dropping a
            // runtime inside an async context panics).
            let serve = tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
                // 8 threads (was 4): this runtime drives the TLS accept loop,
                // Ed448 handshakes, and latency-critical archive↔archive
                // consensus delivery. Heavy hypersync `perform_sync` producers
                // are spawned onto their OWN dedicated runtime (see
                // `hypersync_rt` above), so a flood of sync streams can't
                // occupy these workers and stall the accept/consensus path —
                // that starvation was timing out consensus dials network-wide.
                // The extra headroom keeps the accept loop draining even while
                // this runtime still streams sync RESPONSES (light channel
                // piping; the heavy work happens on the sync runtime).
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(8)
                    .thread_name("peer-grpc")
                    .enable_all()
                    .build()
                    .map_err(anyhow::Error::from)?;
                let res = rt.block_on(async move {
            info!(addr = %addr, "starting peer gRPC (mTLS) on dedicated runtime");
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .map_err(anyhow::Error::from)?;
            // Post-quantum :8340 transport: each connection runs a sntrup761
            // PQNoise handshake (replacing Ed448-mTLS) that authenticates the
            // peer's identity by its signature over the channel-binding hash.
            // The server identity is the FALCON network key (`q-prover-key`) —
            // the migrated transport decodes a Falcon signing key on BOTH ends;
            // handing it the legacy Ed448 seed makes the server's own keypair
            // setup fail and it drops the connection (client sees EOF). Fall
            // back to the Ed448 seed only if the Falcon key is unavailable.
            let pq_seed: Vec<u8> = file_key_manager
                .get_secret_key_bytes_by_id("q-prover-key")
                .unwrap_or_else(|_| seed.to_vec());
            // TLS handshakes run in per-connection tasks with a deadline,
            // never inline in the accept loop — one peer stalling
            // mid-handshake must not block new accepts, and a handshake
            // that never completes must not hold its fd forever.
            //
            // The archive RPC connection limit is intentionally UNBOUNDED:
            // neither the accept backlog nor the concurrent-handshake count
            // is capped, so a legitimate connection (a peer hypersync, an
            // archive↔archive consensus dial) is never dropped because a
            // count was hit. Protection against a connect / TLS-handshake
            // flood is instead time- and fd-bounded: each handshake has a
            // 10 s deadline (half-open sockets self-clean), `raise_fd_limit`
            // lifts RLIMIT_NOFILE, and the h2/tcp keepalives below reap dead
            // peers so fds don't leak. The previous count-based semaphore was
            // belt-and-suspenders once permits were released the instant the
            // crypto finished (no permit is ever held across the enqueue, so
            // the old starvation cascade can't recur regardless).
            let (conn_tx, mut conn_rx) = tokio::sync::mpsc::unbounded_channel::<
                quil_rpc::pqnoise_channel::PqServerStream,
            >();
            let accept_token = peer_grpc_token.clone();
            tokio::spawn(async move {
                loop {
                    let (tcp, _peer) = tokio::select! {
                        r = listener.accept() => match r {
                            Ok(v) => v,
                            Err(e) => {
                                // EMFILE lands here — sleep so fd
                                // exhaustion doesn't become a hot loop.
                                warn!(error = %e, "peer gRPC accept failed");
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                continue;
                            }
                        },
                        _ = accept_token.cancelled() => return,
                    };
                    let tx = conn_tx.clone();
                    let pq_seed = pq_seed.clone();
                    crate::rpc_metrics::inc_connection_accepted();
                    // Handshake runs on the dedicated tls-handshake runtime
                    // (see `tls_handshake_rt`), NOT on the peer-gRPC workers —
                    // Ed448 handshake crypto from a connect storm must never
                    // compete with consensus vote/proposal delivery. The
                    // socket's readiness events still flow through the
                    // peer-gRPC runtime's IO driver (where it was accepted);
                    // only the task execution moves.
                    tls_handshake_rt.spawn(async move {
                        let pq = match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            quil_rpc::pqnoise_channel::pq_server_handshake(tcp, &pq_seed),
                        )
                        .await
                        {
                            Ok(Ok(pq)) => {
                                crate::rpc_metrics::inc_tls_handshake("ok");
                                pq
                            }
                            Ok(Err(e)) => {
                                crate::rpc_metrics::inc_tls_handshake("failed");
                                debug!(error = %e, "PQNoise handshake failed");
                                return;
                            }
                            Err(_) => {
                                crate::rpc_metrics::inc_tls_handshake("timeout");
                                debug!("PQNoise handshake timed out");
                                return;
                            }
                        };
                        // Hand off to tonic. The backlog is unbounded, so this
                        // never blocks and never sheds a completed handshake;
                        // `send` only errors if the receiver (tonic serve loop)
                        // is gone, i.e. the listener is shutting down.
                        if let Err(e) = tx.send(pq) {
                            debug!(error = %e, "peer gRPC accept receiver closed — dropping connection (shutdown)");
                        }
                    });
                }
            });
            let incoming = async_stream::stream! {
                while let Some(tls) = conn_rx.recv().await {
                    yield Ok::<_, std::io::Error>(tls);
                }
            };
            let mut builder = tonic::transport::Server::builder()
                // h2 PING-based reaping of dead peers. This server faces
                // the whole network; without keepalive every peer that
                // disappears without FIN (crash, NAT timeout) leaks one
                // fd permanently — the node eventually dies of EMFILE
                // regardless of how high the ulimit is.
                .http2_keepalive_interval(Some(std::time::Duration::from_secs(20)))
                .http2_keepalive_timeout(Some(std::time::Duration::from_secs(10)))
                // Count every inbound RPC by method path
                // (`rpc_requests_total{path=...}`) — cheap counter bump, no
                // request buffering.
                .layer(crate::rpc_metrics::RpcMetricsLayer)
                .add_service(global_service)
                .add_service(app_shard_service)
                .add_service(key_registry_service)
                .add_service(connectivity_service)
                .add_service(dispatch_service)
                .add_service(mixnet_service)
                .add_service(onion_service);
            if let Some(pp) = pubsub_proxy_service {
                info!("registering PubSubProxy on peer gRPC listener");
                builder = builder.add_service(pp);
            }
            builder
                .serve_with_incoming_shutdown(incoming, async move { peer_grpc_token.cancelled().await; })
                .await
                .map_err(anyhow::Error::from)
                });
                // `rt` is dropped here, inside the blocking thread — legal
                // (dropping a runtime in an async context would panic).
                res
            })
            .await;
            match serve {
                Ok(r) => r,
                Err(join_err) => Err(anyhow::anyhow!(
                    "peer-grpc dedicated runtime thread panicked: {join_err}"
                )),
            }
        });
    } else {
        warn!(addr = %stream_addr, "invalid peer gRPC listen address, server disabled");
    }

    Ok(())
}
