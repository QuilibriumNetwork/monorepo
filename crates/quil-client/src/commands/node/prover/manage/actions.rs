//! Async action commands for the `prover manage` TUI. Port of
//! `manage_actions.go` + the RPC-driving `tea.Cmd`s in `manage_model.go`.
//!
//! Each function performs its RPC work and returns the corresponding
//! [`Msg`]; the event loop spawns them onto the message channel.

use std::sync::Arc;
use std::time::Duration;

use tonic::transport::Channel;

use quil_keys::FileKeyManager;
use quil_types::proto::global::{
    message_request::Request, MessageRequest, ProverLeave, ProverPause, ProverReject, ProverResume,
};
use quil_types::proto::node::{
    node_service_client::NodeServiceClient, GetNodeInfoRequest, GetShardInfoRequest,
    GetWorkerInfoRequest, NodeInfoResponse, RequestJoinRequest, SetManuallyManagedRequest,
};

use super::super::sign;
use super::model::{AwaitFilterEntry, FilterOutcome};
use super::msg::Msg;
use super::shield;
use super::util::{filters_label, trunc_hex};
use crate::context::GlobalArgs;

type Client = NodeServiceClient<Channel>;

/// Per-call deadline for every NodeService RPC (mirrors `rpcTimeout`).
const RPC_TIMEOUT: Duration = Duration::from_secs(15);
/// Longer ceiling for RequestJoin (VDF on the node side).
const JOIN_RPC_TIMEOUT: Duration = Duration::from_secs(90);

/// `allocationStatusNames`.
fn status_name(status: u32) -> String {
    match status {
        0 => "Unknown".to_string(),
        1 => "Joining".to_string(),
        2 => "Active".to_string(),
        3 => "Paused".to_string(),
        4 => "Leaving".to_string(),
        5 => "Rejected".to_string(),
        6 => "Kicked".to_string(),
        n => format!("Unknown({n})"),
    }
}

/// Fetch an authenticated GLOBAL reward witness without waiting on coin scans.
pub async fn fetch_rewards(client: Client, km: Arc<FileKeyManager>) -> Msg {
    #[cfg(feature = "confidential-tokens")]
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        let public = km.get_public_key_bytes_by_id("q-prover-key")?;
        crate::commands::token::balance::read_claimable_rewards(client, &public).await
    })
    .await
    .unwrap_or_else(|_| Err(anyhow::anyhow!("reward query timed out")))
    .map_err(|e| e.to_string());
    #[cfg(not(feature = "confidential-tokens"))]
    let result = {
        let _ = (client, km);
        Err("reward witness support unavailable".into())
    };
    Msg::RewardRefresh(result)
}

/// Longest a legacy read of the Coins tab may take.
const LEGACY_TIMEOUT: Duration = Duration::from_secs(120);

/// Read the legacy coins of the identity with Ed448 key `public` (`None`:
/// the config has none, so it owns no legacy coins).
pub async fn fetch_legacy(
    client: Client,
    public: Option<[u8; 57]>,
    network: u8,
    config_dir: Option<std::path::PathBuf>,
) -> Msg {
    let started = std::time::Instant::now();
    let answer = match public {
        None => Ok(None),
        Some(public) => tokio::time::timeout(
            LEGACY_TIMEOUT,
            crate::commands::token::legacy::snapshot(
                &client,
                &quil_execution::domains::QUIL_TOKEN,
                &public,
                network,
                config_dir.as_deref(),
            ),
        )
        .await
        .unwrap_or_else(|_| {
            Err(anyhow::anyhow!(
                "no answer within {}s",
                LEGACY_TIMEOUT.as_secs()
            ))
        })
        .map(Some)
        .map_err(|e| format!("{e:#}")),
    };
    Msg::LegacyRefresh {
        answer,
        took: started.elapsed(),
    }
}

/// `token shield-all`'s batches for the shield confirmation: read, cut and
/// quoted as the CLI would, nothing proved or submitted. `token` is the
/// manager's global flags and `--max-fee`.
#[cfg(feature = "native-proof")]
pub async fn shield_prepare(token: Option<(GlobalArgs, u128)>) -> Msg {
    use crate::commands::token::{output, TokenCtx};
    // The CLI's progress lines would overwrite the screen.
    let (notes, _ignored) = tokio::sync::mpsc::unbounded_channel();
    let result = output::capture(notes, async {
        let (global, max_fee) = token.ok_or_else(|| anyhow::anyhow!("no node config"))?;
        shield_preview(&TokenCtx::for_manager(global, max_fee)?).await
    })
    .await;
    Msg::ShieldPreview(result.map_err(|e| format!("{e:#}")))
}

/// [`shield_prepare`]'s reads and quotes with `tc`'s node and keys.
#[cfg(feature = "native-proof")]
async fn shield_preview(tc: &crate::commands::token::TokenCtx) -> anyhow::Result<shield::Preview> {
    use crate::commands::token::{plan_shield_all, shield_batch_fee};
    let plan = plan_shield_all(tc, &quil_token(), shield::BATCH_COINS).await?;
    anyhow::ensure!(
        !plan.batches.is_empty(),
        "no unshielded legacy coins on a live shard to shield"
    );
    let (coins, units) = plan.totals()?;
    // One quote per batch size: the price follows the coin count.
    let mut quoted = std::collections::BTreeMap::new();
    let (mut fee, mut fee_max) = (0u128, 0u128);
    for batch in &plan.batches {
        let quote = match quoted.get(&batch.len()) {
            Some(quote) => *quote,
            None => {
                let quote = shield_batch_fee(tc, batch.len()).await?;
                quoted.insert(batch.len(), quote);
                quote
            }
        };
        fee = fee.saturating_add(quote);
        fee_max = fee_max.max(quote);
    }
    Ok(shield::Preview {
        batches: plan.batches.len(),
        coins,
        units,
        fee,
        fee_max,
        max_fee: tc.max_fee,
        recipient: plan.recipient(),
        listed: plan.listed,
        shielded: plan.shielded,
        uncovered: plan.uncovered,
        pending: plan.pending,
        duplicates: plan.duplicates,
    })
}

/// Run the confirmed shield through the CLI's own functions, reporting each
/// batch on `progress`. The batches are read again and must match what was
/// confirmed; otherwise nothing is submitted.
#[cfg(feature = "native-proof")]
pub async fn shield_run(
    token: Option<(GlobalArgs, u128)>,
    preview: shield::Preview,
    progress: tokio::sync::mpsc::UnboundedSender<Msg>,
) -> Msg {
    use crate::commands::token::{output, TokenCtx};
    let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel::<String>();
    let forward = progress.clone();
    tokio::spawn(async move {
        while let Some(line) = lines.recv().await {
            let _ = forward.send(Msg::Shield(shield::Progress::Note(line)));
        }
    });
    let result = output::capture(notes, async {
        let (global, max_fee) = token.ok_or_else(|| anyhow::anyhow!("no node config"))?;
        shield_execute(
            &TokenCtx::for_manager(global, max_fee)?,
            &preview,
            &progress,
        )
        .await
    })
    .await;
    Msg::Shield(shield::Progress::Done(result.map_err(|e| format!("{e:#}"))))
}

/// [`shield_run`]'s work with `tc`'s node and keys.
#[cfg(feature = "native-proof")]
async fn shield_execute(
    tc: &crate::commands::token::TokenCtx,
    preview: &shield::Preview,
    progress: &tokio::sync::mpsc::UnboundedSender<Msg>,
) -> anyhow::Result<()> {
    use crate::commands::token::{execute_shield_all, plan_shield_all, ShieldEvent};
    let plan = plan_shield_all(tc, &quil_token(), shield::BATCH_COINS).await?;
    let (coins, units) = plan.totals()?;
    anyhow::ensure!(
        plan.batches.len() == preview.batches && coins == preview.coins && units == preview.units,
        "the plan changed since it was confirmed ({} batches of {coins} coins now); press ‹S› \
         again",
        plan.batches.len()
    );
    execute_shield_all(tc, plan, |event| {
        let report = match event {
            ShieldEvent::Proving {
                index,
                count,
                coins,
            } => shield::Progress::Proving {
                index,
                count,
                coins,
            },
            ShieldEvent::Skipped { index, count, .. } => shield::Progress::Skipped { index, count },
            ShieldEvent::Submitted {
                index,
                count,
                addresses,
                shielded,
                ..
            } => shield::Progress::Submitted {
                index,
                count,
                addresses,
                shielded,
            },
            ShieldEvent::Nothing { .. } | ShieldEvent::Uncovered(_) => return,
        };
        let _ = progress.send(Msg::Shield(report));
    })
    .await
}

#[cfg(feature = "native-proof")]
fn quil_token() -> String {
    hex::encode(quil_execution::domains::QUIL_TOKEN)
}

/// This build has no shield commands.
#[cfg(not(feature = "native-proof"))]
pub async fn shield_prepare(_token: Option<(GlobalArgs, u128)>) -> Msg {
    Msg::ShieldPreview(Err("this qclient build has no shield commands".into()))
}

#[cfg(not(feature = "native-proof"))]
pub async fn shield_run(
    _token: Option<(GlobalArgs, u128)>,
    _preview: shield::Preview,
    _progress: tokio::sync::mpsc::UnboundedSender<Msg>,
) -> Msg {
    Msg::Shield(shield::Progress::Done(Err(
        "this qclient build has no shield commands".into(),
    )))
}

// ── Data fetch ───────────────────────────────────────────────────────────

/// `fetchRPCData` — GetNodeInfo (required), GetShardInfo + GetWorkerInfo
/// (optional, nil-on-error).
async fn fetch_rpc_data(
    client: &mut Client,
) -> Result<
    (
        NodeInfoResponse,
        Option<quil_types::proto::node::GetShardInfoResponse>,
        Option<quil_types::proto::node::WorkerInfoResponse>,
    ),
    String,
> {
    let node_info = match tokio::time::timeout(
        RPC_TIMEOUT,
        client.get_node_info(tonic::Request::new(GetNodeInfoRequest::default())),
    )
    .await
    {
        Ok(Ok(r)) => r.into_inner(),
        Ok(Err(e)) => return Err(format!("GetNodeInfo: {e}")),
        Err(_) => return Err("GetNodeInfo: timed out".to_string()),
    };

    let shard_info = match tokio::time::timeout(
        RPC_TIMEOUT,
        client.get_shard_info(tonic::Request::new(GetShardInfoRequest {
            include_all: true,
        })),
    )
    .await
    {
        Ok(Ok(r)) => Some(r.into_inner()),
        _ => None,
    };

    let worker_info = match tokio::time::timeout(
        RPC_TIMEOUT,
        client.get_worker_info(tonic::Request::new(GetWorkerInfoRequest::default())),
    )
    .await
    {
        Ok(Ok(r)) => Some(r.into_inner()),
        _ => None,
    };

    Ok((node_info, shard_info, worker_info))
}

/// Fetch fast node/worker status independently of archive-backed shard sizes.
pub async fn fetch_data(mut client: Client) -> Msg {
    let node_info = match tokio::time::timeout(
        RPC_TIMEOUT,
        client.get_node_info(tonic::Request::new(GetNodeInfoRequest::default())),
    )
    .await
    {
        Ok(Ok(r)) => r.into_inner(),
        result => {
            return Msg::DataRefresh {
                node_info: None,
                shard_info: None,
                worker_info: None,
                err: Some(match result {
                    Ok(Err(e)) => format!("GetNodeInfo: {e}"),
                    _ => "GetNodeInfo: timed out".into(),
                }),
            }
        }
    };
    let worker_info = match tokio::time::timeout(
        RPC_TIMEOUT,
        client.get_worker_info(tonic::Request::new(GetWorkerInfoRequest::default())),
    )
    .await
    {
        Ok(Ok(r)) => Some(r.into_inner()),
        _ => None,
    };
    Msg::DataRefresh {
        node_info: Some(node_info),
        shard_info: None,
        worker_info,
        err: None,
    }
}

/// Archive fallback can exceed the fast status deadline. Keep it bounded,
/// report failure explicitly, and allow node status to refresh meanwhile.
pub async fn fetch_shards(mut client: Client) -> Msg {
    let result = tokio::time::timeout(
        Duration::from_secs(60),
        client.get_shard_info(tonic::Request::new(GetShardInfoRequest {
            include_all: true,
        })),
    )
    .await;
    Msg::ShardRefresh(match result {
        Ok(Ok(r)) => Ok(r.into_inner()),
        Ok(Err(e)) => Err(format!("Shard data unavailable: {e}")),
        Err(_) => Err("Shard data timed out after 60s; retrying".into()),
    })
}

/// `getFrameNumber` — current frame from GetShardInfo (the sign frame).
async fn get_frame_number(client: &mut Client) -> Result<u64, String> {
    match tokio::time::timeout(
        RPC_TIMEOUT,
        client.get_shard_info(tonic::Request::new(GetShardInfoRequest::default())),
    )
    .await
    {
        Ok(Ok(r)) => Ok(r.into_inner().frame_number),
        Ok(Err(e)) => Err(format!("get frame number: {e}")),
        Err(_) => Err("get frame number: timed out".to_string()),
    }
}

// ── Join ─────────────────────────────────────────────────────────────────

/// `doJoin` — RequestJoin RPC (VDF runs node-side; longer timeout).
pub async fn do_join(mut client: Client, filters: Vec<Vec<u8>>) -> Msg {
    let label = format!("{} filter(s)", filters.len());
    let err = match tokio::time::timeout(
        JOIN_RPC_TIMEOUT,
        client.request_join(tonic::Request::new(RequestJoinRequest {
            filters: filters.clone(),
            delegate: Vec::new(),
            worker_ids: Vec::new(),
        })),
    )
    .await
    {
        Ok(Ok(_)) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some("RequestJoin timed out".to_string()),
    };
    Msg::ActionResult {
        action: "Join".to_string(),
        filter: label,
        filters_raw: filters,
        err,
    }
}

// ── Signed lifecycle ops (Leave / Confirm / Reject / Pause / Resume) ─────

/// Build the signed `MessageRequest` for a lifecycle action.
#[allow(deprecated)] // ProverReject.filter is a deprecated wire field.
fn build_request(
    km: &FileKeyManager,
    action: &str,
    filters: &[Vec<u8>],
    frame: u64,
) -> anyhow::Result<MessageRequest> {
    let request = match action {
        "Leave" => {
            let sig = sign::leave_sig(km, filters, frame)?;
            Request::Leave(ProverLeave {
                filters: filters.to_vec(),
                frame_number: frame,
                public_key_signature_bls48581: Some(sig),
            })
        }
        "Confirm" => Request::Confirm(sign::confirm_op(km, filters, frame)?),
        "Reject" => {
            let sig = sign::reject_sig(km, filters, frame)?;
            Request::Reject(ProverReject {
                filter: Vec::new(),
                frame_number: frame,
                public_key_signature_bls48581: Some(sig),
                filters: filters.to_vec(),
            })
        }
        "Pause" => {
            let filter = filters.first().cloned().unwrap_or_default();
            let sig = sign::pause_sig(km, &filter, frame)?;
            Request::Pause(ProverPause {
                filter,
                frame_number: frame,
                public_key_signature_bls48581: Some(sig),
            })
        }
        "Resume" => {
            let filter = filters.first().cloned().unwrap_or_default();
            let sig = sign::resume_sig(km, &filter, frame)?;
            Request::Resume(ProverResume {
                filter,
                frame_number: frame,
                public_key_signature_bls48581: Some(sig),
            })
        }
        other => anyhow::bail!("unknown lifecycle action {other}"),
    };
    Ok(MessageRequest {
        timestamp: 0,
        request: Some(request),
    })
}

/// `doLeave`/`doConfirm`/`doReject`/`doPause`/`doResume` + `sendAction`
/// collapsed: fetch the sign frame, build+sign the message, and broadcast
/// it over the global domain.
pub async fn do_lifecycle(
    mut client: Client,
    km: Arc<FileKeyManager>,
    action: String,
    filters: Vec<Vec<u8>>,
    original_status: u32,
) -> Msg {
    let label = if action == "Pause" || action == "Resume" {
        trunc_hex(&hex::encode(filters.first().cloned().unwrap_or_default()))
    } else {
        filters_label(&filters)
    };

    let _ = label; // label mirrors Go's status string; unused in the Rust flow.

    let frame = match get_frame_number(&mut client).await {
        Ok(f) => f,
        Err(e) => {
            return broadcast_err(&action, &filters, original_status, e);
        }
    };

    let request = match build_request(&km, &action, &filters, frame) {
        Ok(r) => r,
        Err(e) => {
            return broadcast_err(&action, &filters, original_status, e.to_string());
        }
    };

    let global_domain = vec![0xFFu8; 32];
    let send = tokio::time::timeout(
        RPC_TIMEOUT,
        crate::send::send_message_request(&mut client, &km, global_domain, request),
    )
    .await;
    let err = match send {
        Ok(Ok(())) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some("broadcast timed out".to_string()),
    };

    Msg::ActionBroadcast {
        action,
        filters_raw: filters,
        send_frame: frame,
        original_status,
        err,
    }
}

fn broadcast_err(action: &str, filters: &[Vec<u8>], original_status: u32, err: String) -> Msg {
    Msg::ActionBroadcast {
        action: action.to_string(),
        filters_raw: filters.to_vec(),
        send_frame: 0,
        original_status,
        err: Some(err),
    }
}

// ── Worker manual-management ─────────────────────────────────────────────

/// `doToggleManual`.
pub async fn do_toggle_manual(mut client: Client, core_id: u32, manual: bool) -> Msg {
    let err = match tokio::time::timeout(
        RPC_TIMEOUT,
        client.set_manually_managed(tonic::Request::new(SetManuallyManagedRequest {
            core_id,
            manually_managed: manual,
        })),
    )
    .await
    {
        Ok(Ok(_)) => None,
        Ok(Err(e)) => Some(e.to_string()),
        Err(_) => Some("timed out".to_string()),
    };
    Msg::ToggleManual {
        core_id,
        new_state: manual,
        err,
    }
}

/// `doMarkWorkersManual` — mark several workers manual (parallel batch).
pub async fn do_mark_workers_manual(client: Client, worker_ids: Vec<u32>) -> Msg {
    let mut handles = Vec::new();
    for id in worker_ids.clone() {
        let mut c = client.clone();
        handles.push(tokio::spawn(async move {
            let r = tokio::time::timeout(
                RPC_TIMEOUT,
                c.set_manually_managed(tonic::Request::new(SetManuallyManagedRequest {
                    core_id: id,
                    manually_managed: true,
                })),
            )
            .await;
            let ok = matches!(r, Ok(Ok(_)));
            (id, ok, format!("{r:?}"))
        }));
    }
    let mut failed = Vec::new();
    let mut first_err = None;
    for h in handles {
        if let Ok((id, ok, dbg)) = h.await {
            if !ok {
                failed.push(id);
                if first_err.is_none() {
                    first_err = Some(dbg);
                }
            }
        }
    }
    Msg::MarkManual {
        worker_ids,
        failed_ids: failed,
        err: first_err,
    }
}

// ── Await confirm ────────────────────────────────────────────────────────

/// `checkAllocationStatus` — poll the node once and resolve each awaited
/// filter's outcome.
pub async fn check_allocation_status(
    mut client: Client,
    action: String,
    entries: Vec<AwaitFilterEntry>,
) -> Msg {
    let (node_info, shard_info, _worker_info) = match fetch_rpc_data(&mut client).await {
        Ok(t) => t,
        Err(e) => {
            return Msg::AwaitResult {
                action,
                frame: 0,
                err: Some(e),
                per_filter: Vec::new(),
            };
        }
    };

    let current_frame = shard_info.as_ref().map(|s| s.frame_number).unwrap_or(0);

    let mut by_filter: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for a in &node_info.shard_allocations {
        by_filter.insert(hex::encode(&a.filter), a.status);
    }

    let outcomes: Vec<FilterOutcome> = entries
        .iter()
        .map(|e| {
            let key = hex::encode(&e.filter);
            match by_filter.get(&key) {
                None => FilterOutcome {
                    filter: e.filter.clone(),
                    outcome: "Removed".to_string(),
                    settled: true,
                },
                Some(&st) if st != e.original_status => FilterOutcome {
                    filter: e.filter.clone(),
                    outcome: status_name(st),
                    settled: true,
                },
                Some(_) => FilterOutcome {
                    filter: e.filter.clone(),
                    outcome: String::new(),
                    settled: false,
                },
            }
        })
        .collect();

    Msg::AwaitResult {
        action,
        frame: current_frame,
        err: None,
        per_filter: outcomes,
    }
}

/// The shield action end to end against a node double: reads, batches and
/// quotes for the confirmation, then the run, whose quotes exceed every
/// batch so nothing is proved or submitted.
#[cfg(all(test, feature = "native-proof"))]
mod shield_action_tests {
    use super::*;
    use quil_types::store::{CoinWitnessProvider, LegacyCoinData, LegacyCoinPageData};
    use std::collections::HashMap;

    struct Coins(HashMap<[u8; 32], Vec<LegacyCoinData>>);
    impl CoinWitnessProvider for Coins {
        fn legacy_coins(
            &self,
            _domain: &[u8; 32],
            owner: &[u8; 32],
            after: Option<&[u8; 32]>,
        ) -> quil_types::error::Result<Option<LegacyCoinPageData>> {
            let coins: Vec<LegacyCoinData> = self
                .0
                .get(owner)
                .into_iter()
                .flatten()
                .filter(|coin| after.is_none_or(|after| coin.address > *after))
                .cloned()
                .collect();
            Ok(Some(LegacyCoinPageData {
                cursor: coins.last().map(|coin| coin.address),
                coins,
                has_more: false,
            }))
        }
    }

    /// One live shard: the QUIL root, which covers every address.
    struct Root;
    impl quil_types::consensus::ShardInfoProvider for Root {
        fn get_shard_info(
            &self,
            _include_all: bool,
        ) -> quil_types::error::Result<(
            Vec<quil_types::consensus::ShardDetail>,
            u64,
            num_bigint::BigInt,
            u64,
            num_bigint::BigInt,
        )> {
            Ok((
                vec![quil_types::consensus::ShardDetail {
                    allocation_reason: None,
                    ring_known: true,
                    filter: quil_execution::domains::QUIL_TOKEN.to_vec(),
                    shard_size: 0.into(),
                    active_provers: 8,
                    ring: 0,
                    estimated_reward: 0.into(),
                    is_allocated: false,
                    data_shards: 1,
                    materialized_frame: 1,
                    latest_frame: 1,
                    prover_counts: None,
                }],
                0,
                0.into(),
                1,
                0.into(),
            ))
        }
    }

    #[tokio::test]
    async fn s_previews_and_runs_through_the_cli_functions() {
        let directory = tempfile::tempdir().unwrap();
        let km = Arc::new(
            FileKeyManager::new(
                directory.path().join("keys.yml"),
                &hex::encode([9; 32]),
                "q-prover-key".into(),
                Box::new(quil_crypto::FalconKeyConstructor),
            )
            .unwrap(),
        );
        km.create_agreement_key("q-onion-key", 9).unwrap();
        let seed = [55; 57];
        let public = quil_crypto::Ed448Signer::derive_public(&seed).unwrap();
        let mut node_config = quil_config::Config::default();
        node_config.p2p.peer_priv_key = hex::encode([&seed[..], &public[..]].concat());
        let owners =
            crate::commands::token::legacy::key_owners(&public.as_slice().try_into().unwrap())
                .unwrap();
        // Three coins under the key owner, one shielded already; another
        // under the peer-id owner.
        let coin = |byte: u8, shielded| LegacyCoinData {
            address: [byte; 32],
            amount: 5,
            origin: [byte ^ 0xff; 32],
            shielded,
        };
        let coins = Coins(HashMap::from([
            (
                owners[0].1,
                vec![coin(0x10, false), coin(0x20, true), coin(0x30, false)],
            ),
            (owners[1].1, vec![coin(0x40, false)]),
        ]));
        let network = quil_execution::token_intrinsic::dispatch::TokenPolicy::for_network(
            node_config.p2p.network,
        )
        .network;
        let server = quil_rpc::node_service::NodeRpcServer::new()
            .with_coin_witness_provider(Arc::new(coins))
            .with_shard_info_provider(Arc::new(Root))
            .with_token_fee_provider(Arc::new(move |_, _| {
                // A small world: each byte of growth costs far more than
                // the five-unit coins, so every batch is skipped unproved.
                Ok(quil_rpc::node_service::TokenFeeSnapshot {
                    network,
                    observed_frame: 42,
                    global_execution: true,
                    difficulty: 50_000,
                    world_state_bytes: 1 << 24,
                    fee_multiplier_vote: 1,
                })
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let multiaddr = format!(
            "/ip4/127.0.0.1/tcp/{}",
            listener.local_addr().unwrap().port()
        );
        let incoming = futures::stream::unfold(listener, |listener| async {
            let result = listener.accept().await.map(|(socket, _)| socket);
            Some((result, listener))
        });
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(
                    quil_types::proto::node::node_service_server::NodeServiceServer::new(server),
                )
                .serve_with_incoming_shutdown(incoming, async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        let opts = crate::rpc::ConnectOpts {
            listen_grpc_multiaddr: multiaddr,
            ..Default::default()
        };
        let tc = crate::commands::token::TokenCtx {
            node_config,
            config_dir: directory.path().to_path_buf(),
            key_manager: km,
            connect_opts: opts.clone(),
            submit_opts: opts,
            peer_id_bytes: Vec::new(),
            max_fee: u128::MAX,
        };
        let (notes, mut lines) = tokio::sync::mpsc::unbounded_channel();
        let preview = crate::commands::token::output::capture(notes, shield_preview(&tc))
            .await
            .unwrap();
        assert_eq!(
            (
                preview.batches,
                preview.coins,
                preview.units,
                preview.uncovered
            ),
            (1, 3, 15, 0)
        );
        // Every listed coin is in a batch or named as left out.
        assert_eq!((preview.listed, preview.shielded), (4, 1));
        assert_eq!(
            preview.coins
                + preview.shielded
                + preview.uncovered
                + preview.pending
                + preview.duplicates,
            preview.listed
        );
        assert!(preview.fee > preview.units && preview.fee == preview.fee_max);
        assert!(preview.recipient.starts_with("0x") && preview.recipient.len() > 66);
        // The fee estimate went to the sink, not the terminal.
        assert!(lines.try_recv().unwrap().starts_with("Estimated fee: "));

        // The run: the model sees the batch skipped and the run end.
        let mut m = super::super::model::Model::new();
        m.coins.shield.dialog = Some(shield::Dialog::Confirm(preview.clone()));
        let cmds = shield::dialog_key(
            &mut m,
            crossterm::event::KeyEvent::from(crossterm::event::KeyCode::Char('y')),
        );
        assert!(matches!(
            cmds.as_slice(),
            [super::super::update::Cmd::ShieldRun(_)]
        ));
        let (progress, mut reports) = tokio::sync::mpsc::unbounded_channel();
        let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
        let result = crate::commands::token::output::capture(
            notes,
            shield_execute(&tc, &preview, &progress),
        )
        .await;
        drop(progress);
        super::super::update::apply_msg(
            &mut m,
            Msg::Shield(shield::Progress::Done(result.map_err(|e| format!("{e:#}")))),
        );
        let mut seen = Vec::new();
        while let Some(Msg::Shield(report)) = reports.recv().await {
            seen.push(report.clone());
            super::super::update::apply_msg(&mut m, Msg::Shield(report));
        }
        assert_eq!(seen, [shield::Progress::Skipped { index: 1, count: 1 }]);
        assert!(!shield::running(&m));
        let run = m.coins.shield.run.as_ref().unwrap();
        assert_eq!((run.skipped, run.submitted.len()), (1, 0));
        assert_eq!(run.done, Some(Ok(())));
        // Nothing went into shield-all's journal.
        assert!(!directory
            .path()
            .join(crate::commands::token::legacy::SHIELD_JOURNAL)
            .exists());

        // A changed plan between confirmation and run submits nothing.
        let mut stale = preview.clone();
        stale.coins = 4;
        let (progress, _reports) = tokio::sync::mpsc::unbounded_channel();
        let (notes, _lines) = tokio::sync::mpsc::unbounded_channel();
        let error =
            crate::commands::token::output::capture(notes, shield_execute(&tc, &stale, &progress))
                .await
                .unwrap_err()
                .to_string();
        assert!(error.contains("the plan changed"), "{error}");
        stop.send(()).unwrap();
        serving.await.unwrap();
    }
}
