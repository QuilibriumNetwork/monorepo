//! `qclient node prover status` — prover status + shard allocations.
//!
//! Port of `client/cmd/node/prover/proverStatus.go`.

use std::collections::HashMap;

use num_bigint::{BigInt, Sign};

use quil_types::proto::node::{
    GetNodeInfoRequest, GetWorkerInfoRequest, NodeInfoResponse, ShardAllocationInfo, WorkerInfo,
};

use super::epoch::{
    action_hints, compute_effective_status, confirmed_phase, epoch_for_frame, epoch_len,
    AllocationTiming, ThresholdClock, ThresholdUnit,
};
use super::{format_storage, worker_by_filter, ProverCtx};

fn timing(a: &ShardAllocationInfo) -> AllocationTiming<'_> {
    AllocationTiming {
        raw_status: a.status,
        filter: &a.filter,
        join_frame: a.join_frame_number,
        join_confirm_frame: a.join_confirm_frame_number,
        leave_frame: a.leave_frame_number,
        leave_confirm_frame: a.leave_confirm_frame_number,
        epoch: a.epoch,
    }
}

/// The running workers against the configured count, with the workers above
/// it that drain: `9 of 6 configured | draining 3`. A node that predates the
/// configured count (0) gets the running count alone.
fn running_workers(running: u32, capacity: u32, draining: usize) -> String {
    let mut text = running.to_string();
    if capacity > 0 {
        text += &format!(" of {capacity} configured");
    }
    if draining > 0 {
        text += &format!(" | draining {draining}");
    }
    text
}

pub async fn run(pc: &ProverCtx) -> anyhow::Result<()> {
    let mut client = pc.connect().await?;

    let info = client
        .get_node_info(tonic::Request::new(GetNodeInfoRequest::default()))
        .await
        .map_err(|e| anyhow::anyhow!("get node info: {e}"))?
        .into_inner();
    let worker_info = client
        .get_worker_info(tonic::Request::new(GetWorkerInfoRequest::default()))
        .await
        .map(|response| response.into_inner().worker_info)
        .ok();
    let workers = if info.shard_allocations.is_empty() {
        HashMap::new()
    } else {
        worker_by_filter(&mut client).await
    };
    print!(
        "{}",
        render(
            &info,
            worker_info.as_deref(),
            &workers,
            crate::verbosity::on()
        )
    );
    Ok(())
}

/// The status report. By default the node's standing, each allocation's
/// status and next action, and each worker's storage; `verbose` adds the
/// peer score, the GLOBAL head, epoch geometry, gossip traffic, each
/// allocation's join/leave/active frames and each worker's local execution.
/// `worker_info`: `None` when the node did not list its workers.
fn render(
    info: &NodeInfoResponse,
    worker_info: Option<&[WorkerInfo]>,
    workers: &HashMap<String, u32>,
    verbose: bool,
) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    let _ = writeln!(out, "Peer ID:            {}", info.peer_id);

    if info.version.len() >= 3 {
        let _ = write!(
            out,
            "Version:            {}.{}.{}",
            info.version[0], info.version[1], info.version[2]
        );
        if !info.patch_number.is_empty() {
            let _ = write!(out, ".{}", info.patch_number[0]);
        }
        let _ = writeln!(out);
    }

    if !info.peer_seniority.is_empty() {
        let s = BigInt::from_bytes_be(Sign::Plus, &info.peer_seniority);
        let _ = writeln!(out, "Seniority:          {s}");
    }

    if verbose {
        let _ = writeln!(out, "Peer Score:         {}", info.peer_score);
    }
    let draining = worker_info
        .unwrap_or_default()
        .iter()
        .filter(|w| w.draining)
        .count();
    let _ = writeln!(
        out,
        "Running Workers:    {}",
        running_workers(info.running_workers, info.worker_capacity, draining)
    );
    let _ = writeln!(out, "Allocated Workers:  {}", info.allocated_workers);
    let _ = writeln!(out, "Last Received:      {}", info.last_received_frame);
    if verbose {
        let _ = writeln!(out, "Last Global Head:   {}", info.last_global_head_frame);
    }

    let epoch_length = info.epoch_length_frames;
    let cur_epoch = info.current_epoch;
    let el = epoch_len(epoch_length);
    let current_frame = info.last_received_frame;
    let next_boundary = (cur_epoch + 1) * el;
    if verbose {
        let _ = writeln!(
            out,
            "Epoch:              {}  (length {} frames; next boundary @ frame {})",
            cur_epoch, el, next_boundary
        );
    } else {
        let _ = writeln!(out, "Epoch:              {cur_epoch}");
    }
    let _ = writeln!(out, "Reachable:          {}", info.reachable);

    if verbose {
        let _ = writeln!(
            out,
            "\n{}",
            super::gossip_traffic::render(
                info.gossip_traffic.as_ref(),
                worker_info.unwrap_or_default()
            )
        );
    }

    if info.shard_allocations.is_empty() {
        let _ = writeln!(out, "\nNo shard allocations");
        return out;
    }

    let _ = writeln!(out, "\nShard Allocations:");
    for (i, alloc) in info.shard_allocations.iter().enumerate() {
        let t = timing(alloc);
        let eff = compute_effective_status(&t, current_frame, epoch_length);
        let filter_hex = hex::encode(&alloc.filter);

        let worker_str = workers
            .get(&filter_hex)
            .map(|wid| format!("  Worker: {wid}"))
            .unwrap_or_default();

        let _ = writeln!(
            out,
            "  [{i}] Filter: {filter_hex}  Status: {}{worker_str}",
            confirmed_phase(&t, eff, epoch_length).map_or(eff.label(), |(name, _)| name)
        );

        // Same vocabulary as the `manage` TUI's Next/Default Action columns:
        // frames left from the received frame, without a time estimate.
        let (next, default) = action_hints(&t, eff, epoch_length, current_frame, next_boundary);
        if !next.is_empty() || !default.is_empty() {
            let (unit, clock) = (
                ThresholdUnit::Relative,
                ThresholdClock {
                    frame: current_frame,
                    seconds_per_frame: None,
                },
            );
            let _ = writeln!(
                out,
                "      Next Action: {}  Default Action: {}",
                next.render(unit, clock),
                default.render(unit, clock)
            );
        }

        if !verbose {
            continue;
        }
        if alloc.join_frame_number > 0 {
            let _ = write!(
                out,
                "      Join Frame: {} (epoch {})",
                alloc.join_frame_number,
                epoch_for_frame(alloc.join_frame_number, epoch_length)
            );
            if alloc.join_confirm_frame_number > 0 {
                let _ = write!(out, "  Confirm Frame: {}", alloc.join_confirm_frame_number);
            }
            let _ = writeln!(out);
        }
        if alloc.leave_frame_number > 0 {
            let _ = write!(
                out,
                "      Leave Frame: {} (epoch {})",
                alloc.leave_frame_number,
                epoch_for_frame(alloc.leave_frame_number, epoch_length)
            );
            if alloc.leave_confirm_frame_number > 0 {
                let _ = write!(out, "  Confirm Frame: {}", alloc.leave_confirm_frame_number);
            }
            let _ = writeln!(out);
        }
        if alloc.last_active_frame_number > 0 {
            let _ = writeln!(out, "      Last Active: {}", alloc.last_active_frame_number);
        }
    }

    // Also display worker info.
    if let Some(worker_info) = worker_info {
        if !worker_info.is_empty() {
            let _ = writeln!(out, "\nWorkers ({}):", worker_info.len());
            for w in worker_info {
                let _ = writeln!(
                    out,
                    "  Core {}: Filter: {}  Storage: {} / {}{}",
                    w.core_id,
                    hex::encode(&w.filter),
                    format_storage(w.available_storage),
                    format_storage(w.total_storage),
                    if w.draining {
                        "  Draining: above the configured count; stops once its seat departs"
                    } else {
                        ""
                    }
                );
                if verbose {
                    let _ = writeln!(
                        out,
                        "    {}",
                        super::local_execution::detail(w.execution.as_ref())
                    );
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node with one allocation joined at frame 100 and one worker.
    fn node() -> (NodeInfoResponse, Vec<WorkerInfo>, HashMap<String, u32>) {
        let info = NodeInfoResponse {
            peer_id: "QmPeer".into(),
            version: vec![2, 1, 0],
            peer_score: 7,
            running_workers: 1,
            worker_capacity: 1,
            allocated_workers: 1,
            last_received_frame: 1_000,
            last_global_head_frame: 999,
            epoch_length_frames: 120,
            current_epoch: 8,
            reachable: true,
            shard_allocations: vec![ShardAllocationInfo {
                filter: vec![0xab; 4],
                status: 1,
                join_frame_number: 100,
                last_active_frame_number: 990,
                ..Default::default()
            }],
            ..Default::default()
        };
        let workers = vec![WorkerInfo {
            core_id: 1,
            filter: vec![0xab; 4],
            available_storage: 1 << 30,
            total_storage: 2 << 30,
            ..Default::default()
        }];
        let by_filter = HashMap::from([(hex::encode([0xab; 4]), 1)]);
        (info, workers, by_filter)
    }

    /// By default: standing, allocations with status and next action,
    /// workers with storage; no frames beyond the received one.
    #[test]
    fn status_shows_standing_allocations_and_workers_by_default() {
        let (info, workers, by_filter) = node();
        let out = render(&info, Some(workers.as_slice()), &by_filter, false);
        for shown in [
            "Peer ID:            QmPeer",
            "Running Workers:    1 of 1 configured",
            "Last Received:      1000",
            "Epoch:              8\n",
            "Reachable:          true",
            "  [0] Filter: abababab  Status: ",
            "  Worker: 1",
            "  Core 1: Filter: abababab  Storage: ",
        ] {
            assert!(out.contains(shown), "{shown:?} missing:\n{out}");
        }
        for hidden in [
            "Peer Score",
            "Last Global Head",
            "next boundary",
            "Gossip Traffic",
            "Join Frame",
            "Last Active",
            "Local execution",
        ] {
            assert!(!out.contains(hidden), "{hidden:?} shown:\n{out}");
        }
    }

    /// `-v` keeps every internal the report had.
    #[test]
    fn status_keeps_its_internals_under_verbose() {
        let (info, workers, by_filter) = node();
        let out = render(&info, Some(workers.as_slice()), &by_filter, true);
        for shown in [
            "Peer Score:         7",
            "Last Global Head:   999",
            "Epoch:              8  (length 120 frames; next boundary @ frame 1080)",
            "Gossip Traffic",
            "      Join Frame: 100 (epoch ",
            "      Last Active: 990",
            "    Local execution: ",
        ] {
            assert!(out.contains(shown), "{shown:?} missing:\n{out}");
        }
    }

    #[test]
    fn running_workers_name_the_configured_count_and_the_draining_ones() {
        assert_eq!(running_workers(9, 6, 3), "9 of 6 configured | draining 3");
        assert_eq!(running_workers(6, 6, 0), "6 of 6 configured");
        assert_eq!(
            running_workers(9, 0, 0),
            "9",
            "a node that predates the configured count"
        );
    }
}
