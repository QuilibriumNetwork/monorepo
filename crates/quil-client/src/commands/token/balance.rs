//! `qclient token balance` — spendable wallet balance plus claimable prover rewards.
//!
//! Port of `client/cmd/token/balance.go`.

use num_bigint::{BigInt, Sign};

use quil_execution::domains::QUIL_TOKEN;
use quil_types::proto::node::{GetProverRewardWitnessRequest, GetTokensByAccountRequest};

use super::TokenCtx;
use crate::util;

/// Decode the current balance of a `reward:ProverReward` witness. A missing
/// vertex is distinct from a present zero balance; a present witness must use
/// the fixed-width encoding promised by the node RPC.
pub(super) fn claimable_reward_value(found: bool, value: &[u8]) -> anyhow::Result<Option<u128>> {
    if !found {
        return Ok(None);
    }
    let value: [u8; 16] = value
        .try_into()
        .map_err(|_| anyhow::anyhow!("reward witness returned a malformed value"))?;
    Ok(Some(u128::from_le_bytes(value)))
}

pub async fn run(tc: &TokenCtx) -> anyhow::Result<()> {
    let mut client = tc.connect().await?;

    // Legacy coins under poseidon(peerId).
    let info = client
        .get_tokens_by_account(tonic::Request::new(GetTokensByAccountRequest {
            address: tc.legacy_address()?,
            domain: QUIL_TOKEN.to_vec(),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("get legacy tokens: {e}"))?
        .into_inner();

    // Transactions + pending under view‖spend.
    let account = tc.view_spend_address()?;
    let txs = client
        .get_tokens_by_account(tonic::Request::new(GetTokensByAccountRequest {
            address: account.clone(),
            domain: QUIL_TOKEN.to_vec(),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("get tokens: {e}"))?
        .into_inner();

    let mut sum = BigInt::from(0);
    for l in &info.legacy_coins {
        if let Some(coin) = &l.coin {
            sum += BigInt::from_bytes_be(Sign::Plus, &coin.amount);
        }
    }
    for t in &txs.transactions {
        sum += BigInt::from_bytes_be(Sign::Plus, &t.raw_balance);
    }
    for p in &txs.pending_transactions {
        sum += BigInt::from_bytes_be(Sign::Plus, &p.raw_balance);
    }

    // Claimable lattice escrows (pending transfers) addressed to this wallet —
    // the "new" balance the legacy(Ed448) + view‖spend queries above miss. Same
    // enumeration `token coins` uses; only escrows addressed TO this wallet count
    // toward balance (refunds are contingent on non-claim + expiration).
    if let Ok(w) = super::lattice::Wallet::load(tc) {
        if let Ok(escrows) =
            super::lattice::list_escrows(&mut client, &QUIL_TOKEN.to_vec()).await
        {
            for e in &escrows {
                if e.to_key != w.falcon_pk {
                    continue;
                }
                if let Some((amt, _)) =
                    quil_execution::token_intrinsic::lattice_ct::open_escrow_memo(
                        w.np, &w.kem_sk, &e.cv, &e.memo,
                    )
                {
                    sum += BigInt::from(amt);
                }
            }
        }
    }

    let formatted = util::float_string_12(&sum, &util::conversion_factor());
    println!(
        "Total balance: {} QUIL (Account 0x{})",
        formatted,
        hex::encode(&account)
    );

    // Rewards live in a separate mutable prover vertex and are not spendable
    // until `qclient token mint` submits a mint transaction.  Query the exact
    // same witness used by that command, but do not request or submit a proof.
    match super::lattice::Wallet::load(tc) {
        Ok(wallet) => {
            let owner = quil_crypto::poseidon::hash_bytes_to_32(&wallet.falcon_pk)
                .map_err(|e| anyhow::anyhow!("prover address: {e}"))?
                .to_vec();
            let reward = client
                .get_prover_reward_witness(tonic::Request::new(GetProverRewardWitnessRequest {
                    domain: QUIL_TOKEN.to_vec(),
                    owner_prover_address: owner,
                }))
                .await
                .map_err(|e| anyhow::anyhow!("GetProverRewardWitness: {e}"))?
                .into_inner();
            match claimable_reward_value(reward.found, &reward.value)? {
                None => println!("Claimable prover rewards: unavailable (no reward record found)"),
                Some(claimable) => {
                    let claimable_display =
                        util::float_string_12(&BigInt::from(claimable), &util::conversion_factor());
                    println!(
                        "Claimable prover rewards: {claimable_display} QUIL \
                         (proven at global frame {})",
                        reward.cited_frame
                    );
                    if claimable != 0 {
                        let total_after_minting = sum + BigInt::from(claimable);
                        println!(
                            "Total after minting: {} QUIL",
                            util::float_string_12(&total_after_minting, &util::conversion_factor())
                        );
                    }
                }
            }
        }
        Err(_) => println!("Claimable prover rewards: unavailable (prover wallet unavailable)"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::claimable_reward_value;

    #[test]
    fn missing_reward_witness_is_distinct_from_a_zero_balance() {
        assert_eq!(claimable_reward_value(false, &[]).unwrap(), None);
    }

    #[test]
    fn reward_witness_value_is_little_endian_u128() {
        assert_eq!(
            claimable_reward_value(true, &123_456_789u128.to_le_bytes()).unwrap(),
            Some(123_456_789),
        );
    }

    #[test]
    fn present_reward_witness_requires_fixed_width_value() {
        assert!(claimable_reward_value(true, &[0; 15]).is_err());
    }
}
