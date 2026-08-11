//! `qclient token transfer <RecipientAddress> <Amount>` — a post-quantum
//! confidential transfer.
//!
//! Client wiring over the (tested) lattice confidential-transaction pipeline:
//! `ListDomainCoins` → scan → `GetCoinSpendWitness` → `build_spend_transaction`
//! → submit the `0x0512` message. The shared scan/select/witness/build/submit
//! machinery lives in [`super::lattice`].
//!
//! Simplifications (documented, first-cut): `fee = 0`; the `<Amount>` argument
//! is a **decimal QUIL** value (e.g. `1`, `1.5`, `0.02`), converted to base
//! units via `util::conversion_factor()` (1 QUIL = 8e9 base units) exactly as
//! the Go client does; a recipient address is `hex(kem_pk ‖ wire(B))`. A
//! lattice tx is self-authenticating (its spend proof is the authority), so no
//! outer Ed448 signature is used.

use super::lattice::{fetch_inputs, parse_address, scan_owned_coins, select_to_cover, submit_spend, OutSpec, Wallet};
use super::TokenCtx;

pub async fn run(tc: &TokenCtx, recipient: &str, amount: &str) -> anyhow::Result<()> {
    // `<Amount>` is decimal QUIL; convert to base units (× 8e9), like Go's
    // shopspring `decimal.NewFromString(..).Mul(conversionFactor).BigInt()`.
    let transfer_amount: u128 = crate::util::parse_quil_amount(amount)?;
    let domain = quil_execution::domains::QUIL_TOKEN.to_vec();

    let w = Wallet::load(tc)?;
    let recipient_addr = parse_address(recipient)?;
    let mut client = tc.connect().await?;

    let owned = scan_owned_coins(&mut client, &domain, &w).await?;
    if owned.is_empty() {
        anyhow::bail!("no spendable coins found in this account");
    }
    let (selected, total) = select_to_cover(owned, transfer_amount)?;
    let (root, depth, inputs) = fetch_inputs(&mut client, &domain, &selected).await?;

    // Outputs: recipient + change-to-self.
    let mut out_specs = vec![OutSpec {
        amount: transfer_amount,
        kem_target: recipient_addr.kem_pk,
        b_target: recipient_addr.big_b,
    }];
    let change = total - transfer_amount;
    if change > 0 {
        out_specs.push(OutSpec {
            amount: change,
            kem_target: w.kem_pk.clone(),
            b_target: w.big_b.clone(),
        });
    }

    submit_spend(&mut client, &w, &domain, &root, depth, &inputs, &out_specs).await?;

    println!(
        "Transfer submitted: {transfer_amount} to recipient (change {change}), {} input(s)",
        inputs.len()
    );
    Ok(())
}
