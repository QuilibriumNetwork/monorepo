//! `qclient node prover status` — prover status + shard allocations.
//!
//! Port of `client/cmd/node/prover/proverStatus.go`.

use num_bigint::{BigInt, Sign};

use quil_types::proto::node::{GetNodeInfoRequest, GetWorkerInfoRequest, ShardAllocationInfo};

use super::epoch::{
    alloc_confirm_window, compute_effective_status, epoch_for_frame, epoch_len, AllocationTiming,
    EffectiveStatus,
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
    println!("Running Workers:    {}", info.running_workers);
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
            eff.label()
        );

        if let Some(w) = alloc_confirm_window(&t, epoch_length) {
            println!(
                "      Action: {} | {}",
                w.label("Confirm", current_frame, epoch_length),
                w.label("Reject", current_frame, epoch_length)
            );
        } else if eff == EffectiveStatus::Active && !alloc.filter.is_empty() {
            println!(
                "      Re-confirm through epoch {} (renew before frame {})",
                alloc.epoch, next_boundary
            );
        } else if eff == EffectiveStatus::ExpiredEpoch {
            println!(
                "      MISSED re-confirm (registered epoch {} < current {}) — confirm now to restore",
                alloc.epoch, cur_epoch
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
    if let Ok(worker_info) = client
        .get_worker_info(tonic::Request::new(GetWorkerInfoRequest::default()))
        .await
    {
        let worker_info = worker_info.into_inner();
        if !worker_info.worker_info.is_empty() {
            println!("\nWorkers ({}):", worker_info.worker_info.len());
            for w in &worker_info.worker_info {
                println!(
                    "  Core {}: Filter: {}  Storage: {} / {}",
                    w.core_id,
                    hex::encode(&w.filter),
                    format_storage(w.available_storage),
                    format_storage(w.total_storage)
                );
            }
        }
    }

    Ok(())
}
