//! `qclient token coins` — list every coin (legacy, active, pending).
//!
//! Port of `client/cmd/token/coins.go`.

use quil_execution::domains::QUIL_TOKEN;
use quil_types::proto::node::GetTokensByAccountRequest;

use super::TokenCtx;
use crate::util;

pub async fn run(tc: &TokenCtx) -> anyhow::Result<()> {
    let mut client = tc.connect().await?;

    let info = client
        .get_tokens_by_account(tonic::Request::new(GetTokensByAccountRequest {
            address: tc.legacy_address()?,
            domain: QUIL_TOKEN.to_vec(),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("get legacy tokens: {e}"))?
        .into_inner();

    let account = tc.view_spend_address()?;
    let txs = client
        .get_tokens_by_account(tonic::Request::new(GetTokensByAccountRequest {
            address: account,
            domain: QUIL_TOKEN.to_vec(),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("get tokens: {e}"))?
        .into_inner();

    let mut count = 0;
    for l in &info.legacy_coins {
        let amount = l.coin.as_ref().map(|c| c.amount.as_slice()).unwrap_or(&[]);
        println!(
            "{} QUIL (Legacy Coin 0x{})",
            util::format_quil(amount),
            hex::encode(&l.address)
        );
        count += 1;
    }
    for t in &txs.transactions {
        println!(
            "{} QUIL (Coin 0x{})",
            util::format_quil(&t.raw_balance),
            hex::encode(&t.address)
        );
        count += 1;
    }
    for p in &txs.pending_transactions {
        println!(
            "{} QUIL (Pending 0x{})",
            util::format_quil(&p.raw_balance),
            hex::encode(&p.address)
        );
        count += 1;
    }

    // Claimable lattice escrows (pending transfers) addressed to this wallet.
    if let Ok(w) = super::lattice::Wallet::load(tc) {
        if let Ok(escrows) = super::lattice::list_escrows(&mut client, &QUIL_TOKEN.to_vec()).await {
            for e in &escrows {
                let mine_to = e.to_key == w.falcon_pk;
                let mine_refund = e.refund_key == w.falcon_pk;
                if !mine_to && !mine_refund {
                    continue;
                }
                let Some((amt, _)) = quil_execution::token_intrinsic::lattice_ct::open_escrow_memo(
                    w.np, &w.kem_sk, &e.cv, &e.memo,
                ) else {
                    continue;
                };
                let role = if mine_to {
                    "accept".to_string()
                } else {
                    format!("refund @frame {}", e.expiration)
                };
                println!(
                    "{} base units (Escrow 0x{} — {})",
                    amt,
                    hex::encode(&e.address),
                    role
                );
                count += 1;
            }
        }
    }

    if count == 0 {
        println!("No coins found");
    }
    Ok(())
}
