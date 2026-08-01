//! `qclient token merge [all | <Coin>...]` — merge several confidential coins
//! into one.
//!
//! Lattice port of `client/cmd/token/merge.go`: spend the selected coins as
//! inputs and create a single self-output equal to their sum (fee = 0). A coin
//! is identified by the `address` shown by `token coins` (or its one-time key).

use super::lattice::{
    address_to_otk, fetch_inputs, resolve_otk, scan_owned_coins, submit_spend, OutSpec, Wallet,
};
use super::TokenCtx;

pub async fn run(tc: &TokenCtx, coins: &[String]) -> anyhow::Result<()> {
    let domain = quil_execution::domains::QUIL_TOKEN.to_vec();
    let w = Wallet::load(tc)?;
    let mut client = tc.connect().await?;

    let owned = scan_owned_coins(&mut client, &domain, &w).await?;
    if owned.is_empty() {
        anyhow::bail!("no spendable coins found in this account");
    }

    // Select which coins to merge.
    let merge_all = coins.is_empty() || (coins.len() == 1 && coins[0].eq_ignore_ascii_case("all"));
    let selected = if merge_all {
        owned
    } else {
        let addr_map = address_to_otk(&mut client, tc).await?;
        let mut want: Vec<Vec<u8>> = Vec::new();
        for c in coins {
            want.push(resolve_otk(c, &addr_map)?);
        }
        let selected: Vec<_> = owned
            .into_iter()
            .filter(|c| want.iter().any(|w| *w == c.p_bytes))
            .collect();
        if selected.len() != want.len() {
            anyhow::bail!(
                "matched {} of {} requested coins as spendable (are they owned + confirmed?)",
                selected.len(),
                want.len()
            );
        }
        selected
    };

    if selected.len() < 2 {
        anyhow::bail!("need at least 2 spendable coins to merge (have {})", selected.len());
    }

    let total: u128 = selected.iter().map(|c| c.amount).sum();
    let (root, depth, inputs) = fetch_inputs(&mut client, &domain, &selected).await?;

    let out_specs = vec![OutSpec {
        amount: total,
        kem_target: w.kem_pk.clone(),
        b_target: w.big_b.clone(),
    }];
    submit_spend(&mut client, &w, &domain, &root, depth, &inputs, &out_specs).await?;

    println!(
        "Merge submitted: {} coin(s) → 1 coin of {total} base units",
        inputs.len()
    );
    Ok(())
}
