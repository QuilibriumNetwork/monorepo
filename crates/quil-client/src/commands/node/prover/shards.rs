//! `qclient node prover shards` — allocated shards + estimated rewards.
//!
//! Port of `client/cmd/node/prover/proverShards.go`.

use num_bigint::{BigInt, Sign};

use quil_types::proto::node::GetShardInfoRequest;

use super::{format_quil_daily_round, format_storage, worker_by_filter, ProverCtx};

pub async fn run(pc: &ProverCtx) -> anyhow::Result<()> {
    let mut client = pc.connect().await?;

    let resp = client
        .get_shard_info(tonic::Request::new(GetShardInfoRequest {
            include_all: false,
        }))
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
    let mut unknown = 0;
    let mut adjusted = [BigInt::from(0), BigInt::from(0)];
    let mut adjusted_known = [0usize; 2];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    for shard in &resp.shards {
        let filter_hex = hex::encode(&shard.filter);
        let worker_str = workers
            .get(&filter_hex)
            .map(|wid| format!("  Worker: {wid}"))
            .unwrap_or_default();

        let reward = BigInt::from_bytes_be(Sign::Plus, &shard.estimated_reward);
        if shard.ring_known == Some(false) {
            unknown += 1;
        } else {
            total += &reward;
        }

        let forecasts: Vec<_> = [false, true]
            .iter()
            .enumerate()
            .map(|(i, day)| {
                let value = if shard.ring_known == Some(false) {
                    None
                } else {
                    shard
                        .frame_cadence
                        .as_ref()
                        .and_then(|c| super::observed_quil_daily(&reward, c, *day, now))
                };
                if let Some(v) = value {
                    adjusted[i] += &v;
                    adjusted_known[i] += 1;
                    super::format_quil_daily_units(&v)
                } else {
                    "-".into()
                }
            })
            .collect();
        println!(
            "  Filter: {}  Shards: {:<6} Provers: {:<4} Ring: {}  Reward [Q/d 60m/24h/theory]: {}/{}/{}{}",
            filter_hex,
            shard.data_shards,
            shard.active_provers,
            if shard.ring_known == Some(false) { "-".into() } else { shard.ring.to_string() },
            forecasts[0], forecasts[1],
            if shard.ring_known == Some(false) { "-".into() } else { super::format_quil_daily_units(&(&reward * BigInt::from(8640))) },
            worker_str
        );
    }

    println!(
        "\n{} estimated (theoretical, 10s/frame): {} Q/d",
        if unknown > 0 { "Known" } else { "Total" },
        format_quil_daily_round(&total)
    );
    println!(
        "Observed-cadence estimates [Q/d 60m/24h]: {}",
        (0..2)
            .map(|i| if adjusted_known[i] == 0 {
                "-".into()
            } else {
                format!(
                    "{}{}",
                    super::format_quil_daily_units(&adjusted[i]),
                    if adjusted_known[i] < resp.shards.len() {
                        "+"
                    } else {
                        ""
                    }
                )
            })
            .collect::<Vec<_>>()
            .join("/")
    );
    if unknown > 0 {
        println!("Unknown reward estimates: {unknown}");
    }
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
