//! `qclient node prover status` — prover status + shard allocations.
//!
//! Port of `client/cmd/node/prover/proverStatus.go`.

use num_bigint::{BigInt, Sign};

use quil_types::proto::node::{GetNodeInfoRequest, GetWorkerInfoRequest, ShardAllocationInfo};

use super::epoch::{
    action_hints, compute_effective_status, confirmed_phase, epoch_for_frame, epoch_len, AllocationTiming,
    ThresholdClock, ThresholdUnit,
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

    println!("Peer ID:            {}", info.peer_id);

    if info.version.len() >= 3 {
        print!(
            "Version:            {}.{}.{}",
            info.version[0], info.version[1], info.version[2]
        );
        if !info.patch_number.is_empty() {
            print!(".{}", info.patch_number[0]);
        }
        println!();
    }

    if !info.peer_seniority.is_empty() {
        let s = BigInt::from_bytes_be(Sign::Plus, &info.peer_seniority);
        println!("Seniority:          {s}");
    }

    println!("Peer Score:         {}", info.peer_score);
    let draining = match client.get_worker_info(tonic::Request::new(GetWorkerInfoRequest::default())).await {
        Ok(workers) => workers.into_inner().worker_info.iter().filter(|w| w.draining).count(),
        Err(_) => 0,
    };
    println!("Running Workers:    {}", running_workers(info.running_workers, info.worker_capacity, draining));
    println!("Allocated Workers:  {}", info.allocated_workers);
    println!("Last Received:      {}", info.last_received_frame);
    println!("Last Global Head:   {}", info.last_global_head_frame);

    let epoch_length = info.epoch_length_frames;
    let cur_epoch = info.current_epoch;
    let el = epoch_len(epoch_length);
    let current_frame = info.last_received_frame;
    let next_boundary = (cur_epoch + 1) * el;
    println!(
        "Epoch:              {}  (length {} frames; next boundary @ frame {})",
        cur_epoch, el, next_boundary
    );
    println!("Reachable:          {}", info.reachable);

    let worker_info = client
        .get_worker_info(tonic::Request::new(GetWorkerInfoRequest::default()))
        .await
        .map(|response| response.into_inner().worker_info);
    let workers_listed = worker_info.as_deref().unwrap_or_default();
    println!("\n{}", super::gossip_traffic::render(info.gossip_traffic.as_ref(), workers_listed));

    if info.shard_allocations.is_empty() {
        println!("\nNo shard allocations");
        return Ok(());
    }

    let workers = worker_by_filter(&mut client).await;

    println!("\nShard Allocations:");
    for (i, alloc) in info.shard_allocations.iter().enumerate() {
        let t = timing(alloc);
        let eff = compute_effective_status(&t, current_frame, epoch_length);
        let filter_hex = hex::encode(&alloc.filter);

        let worker_str = workers
            .get(&filter_hex)
            .map(|wid| format!("  Worker: {wid}"))
            .unwrap_or_default();

        println!(
            "  [{i}] Filter: {filter_hex}  Status: {}{worker_str}",
            confirmed_phase(&t, eff, epoch_length).map_or(eff.label(), |(name, _)| name)
        );

        // Same vocabulary as the `manage` TUI's Next/Default Action columns:
        // frames left from the received frame, without a time estimate.
        let (next, default) = action_hints(&t, eff, epoch_length, current_frame, next_boundary);
        if !next.is_empty() || !default.is_empty() {
            let (unit, clock) = (ThresholdUnit::Relative, ThresholdClock { frame: current_frame, seconds_per_frame: None });
            println!(
                "      Next Action: {}  Default Action: {}",
                next.render(unit, clock),
                default.render(unit, clock)
            );
        }

        if alloc.join_frame_number > 0 {
            print!(
                "      Join Frame: {} (epoch {})",
                alloc.join_frame_number,
                epoch_for_frame(alloc.join_frame_number, epoch_length)
            );
            if alloc.join_confirm_frame_number > 0 {
                print!("  Confirm Frame: {}", alloc.join_confirm_frame_number);
            }
            println!();
        }
        if alloc.leave_frame_number > 0 {
            print!(
                "      Leave Frame: {} (epoch {})",
                alloc.leave_frame_number,
                epoch_for_frame(alloc.leave_frame_number, epoch_length)
            );
            if alloc.leave_confirm_frame_number > 0 {
                print!("  Confirm Frame: {}", alloc.leave_confirm_frame_number);
            }
            println!();
        }
        if alloc.last_active_frame_number > 0 {
            println!("      Last Active: {}", alloc.last_active_frame_number);
        }
    }

    // Also display worker info.
    if let Ok(worker_info) = worker_info {
        if !worker_info.is_empty() {
            println!("\nWorkers ({}):", worker_info.len());
            for w in &worker_info {
                println!(
                    "  Core {}: Filter: {}  Storage: {} / {}{}",
                    w.core_id,
                    hex::encode(&w.filter),
                    format_storage(w.available_storage),
                    format_storage(w.total_storage),
                    if w.draining { "  Draining: above the configured count; stops once its seat departs" } else { "" }
                );
                println!("    {}", super::local_execution::detail(w.execution.as_ref()));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::running_workers;

    #[test]
    fn running_workers_name_the_configured_count_and_the_draining_ones() {
        assert_eq!(running_workers(9, 6, 3), "9 of 6 configured | draining 3");
        assert_eq!(running_workers(6, 6, 0), "6 of 6 configured");
        assert_eq!(running_workers(9, 0, 0), "9", "a node that predates the configured count");
    }
}
