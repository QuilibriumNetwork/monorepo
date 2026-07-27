//! `qclient token balance` — sum of legacy + tx + pending balances.
//!
//! Port of `client/cmd/token/balance.go`.

use num_bigint::{BigInt, Sign};

use quil_execution::domains::QUIL_TOKEN;
use quil_types::proto::node::GetTokensByAccountRequest;

use super::TokenCtx;
use crate::util;

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

    let formatted = util::float_string_12(&sum, &util::conversion_factor());
    println!(
        "Total balance: {} QUIL (Account 0x{})",
        formatted,
        hex::encode(&account)
    );
    Ok(())
}
