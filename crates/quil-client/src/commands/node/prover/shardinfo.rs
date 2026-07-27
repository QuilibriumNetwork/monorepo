//! `qclient node prover shardinfo` — every known shard.
//!
//! Port of `client/cmd/node/prover/proverShardInfo.go`.

use num_bigint::{BigInt, Sign};

use quil_types::proto::node::GetShardInfoRequest;

use super::{format_quil_reward, format_storage, worker_by_filter, ProverCtx};

pub async fn run(pc: &ProverCtx) -> anyhow::Result<()> {
    let mut client = pc.connect().await?;

    let resp = client
        .get_shard_info(tonic::Request::new(GetShardInfoRequest { include_all: true }))
        .await
        .map_err(|e| anyhow::anyhow!("get shard info: {e}"))?
        .into_inner();

    if resp.shards.is_empty() {
        println!("No shards found");
        return Ok(());
    }

    let workers = worker_by_filter(&mut client).await;

    println!("All Shards ({} shards):", resp.shards.len());

    for shard in &resp.shards {
        let filter_hex = hex::encode(&shard.filter);

        let suffix = if shard.is_allocated {
            match workers.get(&filter_hex) {
                Some(wid) => format!("  [Worker {wid}]"),
                None => "  [ACTIVE]".to_string(),
            }
        } else {
            String::new()
        };

        let shard_size = BigInt::from_bytes_be(Sign::Plus, &shard.shard_size);
        let reward = BigInt::from_bytes_be(Sign::Plus, &shard.estimated_reward);
        let shard_size_u64 = u64::try_from(shard_size).unwrap_or(u64::MAX);

        println!(
            "  Filter: {}  Size: {:<10} Shards: {:<6} Provers: {:<4} Ring: {}  Reward: ~{} QUIL/frame{}",
            filter_hex,
            format_storage(shard_size_u64),
            shard.data_shards,
            shard.active_provers,
            shard.ring,
            format_quil_reward(&reward),
            suffix
        );
    }

    println!(
        "\nDifficulty: {}  Frame: {}",
        resp.difficulty, resp.frame_number
    );

    let world = BigInt::from_bytes_be(Sign::Plus, &resp.world_state_bytes);
    if world.sign() == Sign::Plus {
        let world_u64 = u64::try_from(world).unwrap_or(u64::MAX);
        println!("World State: {}", format_storage(world_u64));
    }

    let basis = BigInt::from_bytes_be(Sign::Plus, &resp.pomw_basis);
    if basis.sign() == Sign::Plus {
        println!("PomW Basis: {basis}");
    }
    Ok(())
}
