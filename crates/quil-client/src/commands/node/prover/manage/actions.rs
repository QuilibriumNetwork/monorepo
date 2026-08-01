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
    message_request::Request, MessageRequest, ProverConfirm, ProverLeave, ProverPause,
    ProverReject, ProverResume,
};
use quil_types::proto::node::{
    node_service_client::NodeServiceClient, GetNodeInfoRequest, GetShardInfoRequest,
    GetWorkerInfoRequest, NodeInfoResponse, RequestJoinRequest, SetManuallyManagedRequest,
};

use super::super::sign;
use super::model::{AwaitFilterEntry, FilterOutcome};
use super::msg::Msg;
use super::util::{filters_label, trunc_hex};

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
        client.get_shard_info(tonic::Request::new(GetShardInfoRequest { include_all: true })),
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

/// `fetchData` — full refresh.
pub async fn fetch_data(mut client: Client) -> Msg {
    match fetch_rpc_data(&mut client).await {
        Ok((node_info, shard_info, worker_info)) => Msg::DataRefresh {
            node_info: Some(node_info),
            shard_info,
            worker_info,
            err: None,
        },
        Err(e) => Msg::DataRefresh {
            node_info: None,
            shard_info: None,
            worker_info: None,
            err: Some(e),
        },
    }
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
#[allow(deprecated)] // ProverConfirm/ProverReject.filter is a deprecated wire field.
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
        "Confirm" => {
            let sig = sign::confirm_sig(km, filters, frame)?;
            Request::Confirm(ProverConfirm {
                filter: Vec::new(),
                frame_number: frame,
                public_key_signature_bls48581: Some(sig),
                filters: filters.to_vec(),
                leaf_roots: Vec::new(),
            })
        }
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
