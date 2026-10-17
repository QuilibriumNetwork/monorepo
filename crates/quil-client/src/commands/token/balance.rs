//! Read-only prover rewards, independent of the application's wallet coin scan.

use super::{wallet::RecipientWallet, TokenCtx};
use quil_types::proto::node::{
    node_service_client::NodeServiceClient, GetProverRewardWitnessRequest,
};
use tonic::transport::Channel;

pub(super) async fn claimable_rewards(tc: &TokenCtx) -> String {
    // Rewards are GLOBAL state held by the configured node. --read-rpc may
    // name a worker holding application coins, so it is not used for this read.
    let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let public = tc.key_manager.get_public_key_bytes_by_id("q-prover-key")?;
        let client = tc.connect_submit().await?;
        read_claimable_rewards(client, &public).await
    })
    .await
    .unwrap_or_else(|_| Err(anyhow::anyhow!("reward query timed out")));
    format_claimable_rewards(result)
}

pub(crate) async fn read_claimable_rewards(
    client: NodeServiceClient<Channel>,
    public: &[u8],
) -> anyhow::Result<Option<(u128, u64)>> {
    let public: [u8; 897] = public
        .try_into()
        .map_err(|_| anyhow::anyhow!("prover key is not Falcon-512"))?;
    let owner = quil_crypto::poseidon::hash_bytes_to_32(&public)?;
    let response = client
        .max_decoding_message_size(64 * 1024)
        .get_prover_reward_witness(GetProverRewardWitnessRequest {
            domain: quil_execution::domains::QUIL_TOKEN.to_vec(),
            owner_prover_address: owner.to_vec(),
        })
        .await?
        .into_inner();
    // The RPC uses found=false for both absent and zero-valued records.
    // Neither authenticates a zero balance, so do not print one.
    if !response.found {
        return Ok(None);
    }
    let (frame, _, claim) = RecipientWallet::decode_reward_claim(public, response)?;
    Ok(Some((claim.value, frame)))
}

fn format_claimable_rewards(result: anyhow::Result<Option<(u128, u64)>>) -> String {
    match result {
        Ok(Some((value, frame))) => format!(
            "Claimable prover rewards: {} QUIL (witness cites global frame {frame}; requires minting)",
            crate::util::float_string_12(&num_bigint::BigInt::from(value), &crate::util::conversion_factor()),
        ),
        Ok(None) => "Claimable prover rewards: unavailable (no claimable reward witness returned)".into(),
        Err(error) => format!("Claimable prover rewards: unavailable ({error})"),
    }
}

#[cfg(test)]
#[path = "balance_tests.rs"]
mod tests;
