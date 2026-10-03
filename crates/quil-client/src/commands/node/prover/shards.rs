//! `qclient node prover shards` — allocated shards + estimated rewards.
//!
//! Port of `client/cmd/node/prover/proverShards.go`.

use num_bigint::{BigInt, Sign};

use quil_types::proto::node::GetShardInfoRequest;

use super::{format_quil_daily, format_quil_reward, format_storage, worker_by_filter, ProverCtx};

pub async fn run(pc: &ProverCtx) -> anyhow::Result<()> {
    let mut client = pc.connect().await?;

    let resp = client
        .get_shard_info(tonic::Request::new(GetShardInfoRequest { include_all: false }))
        .await
        .map_err(|e| anyhow::anyhow!("get shard info: {e}"))?
        .into_inner();

    if resp.shards.is_empty() {
        println!("No allocated shards");
        return Ok(());
    }

    let workers = worker_by_filter(&mut client).await;

    println!("Shard Rewards ({} shards):", resp.shards.len());

    let mut total = BigInt::from(0);
    for shard in &resp.shards {
        let filter_hex = hex::encode(&shard.filter);
        let worker_str = workers
            .get(&filter_hex)
            .map(|wid| format!("  Worker: {wid}"))
            .unwrap_or_default();

        let reward = BigInt::from_bytes_be(Sign::Plus, &shard.estimated_reward);
        total += &reward;

        println!(
            "  Filter: {}  Shards: {:<6} Provers: {:<4} Ring: {}  Reward: ~{} QUIL/frame{}",
            filter_hex,
            shard.data_shards,
            shard.active_provers,
            shard.ring,
            format_quil_reward(&reward),
            worker_str
        );
    }

    println!(
        "\nTotal estimated: ~{} QUIL/frame (~{} QUIL/day)",
        format_quil_reward(&total),
        format_quil_daily(&total)
    );
    println!(
        "Difficulty: {}  Frame: {}",
        resp.difficulty, resp.frame_number
    );

    let world = BigInt::from_bytes_be(Sign::Plus, &resp.world_state_bytes);
    if world.sign() == Sign::Plus {
        // world fits in u64 for display.
        let world_u64 = u64::try_from(world).unwrap_or(u64::MAX);
        println!("World State: {}", format_storage(world_u64));
    }
    Ok(())
}
