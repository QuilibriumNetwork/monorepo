//! `qclient token split <Coin> <Amounts>...` / `--parts N [--part-amount A]` —
//! split one confidential coin into several.
//!
//! Lattice port of `client/cmd/token/split.go`: spend the one selected coin and
//! create the requested self-outputs (plus a remainder coin so outputs sum
//! exactly to the input, fee = 0). Amounts are raw base units (matching
//! `token transfer`), not decimal QUIL. A coin is identified by the `address`
//! shown by `token coins` (or its one-time key).

use super::lattice::{
    address_to_otk, fetch_inputs, resolve_otk, scan_owned_coins, submit_spend, OutSpec, Wallet,
};
use super::TokenCtx;

const MAX_PARTS: u32 = 100;

pub async fn run(
    tc: &TokenCtx,
    coin: &str,
    amounts: &[String],
    parts: Option<u32>,
    part_amount: Option<&str>,
) -> anyhow::Result<()> {
    // Validate the mutually-exclusive argument shapes (mirrors split.go).
    if parts.is_some() && !amounts.is_empty() {
        anyhow::bail!("--parts can't be combined with explicit <Amounts>");
    }
    if part_amount.is_some() && parts.is_none() {
        anyhow::bail!("--part-amount requires --parts");
    }
    if parts.is_none() && amounts.is_empty() {
        anyhow::bail!("specify either <Amounts>... or --parts N");
    }
    if let Some(n) = parts {
        if n < 1 {
            anyhow::bail!("--parts must be at least 1");
        }
        if n > MAX_PARTS {
            anyhow::bail!("too many parts, maximum is {MAX_PARTS}");
        }
    }

    let domain = quil_execution::domains::QUIL_TOKEN.to_vec();
    let w = Wallet::load(tc)?;
    let mut client = tc.connect().await?;

    let owned = scan_owned_coins(&mut client, &domain, &w).await?;
    if owned.is_empty() {
        anyhow::bail!("no spendable coins found in this account");
    }

    // Resolve the source coin.
    let addr_map = address_to_otk(&mut client, tc).await?;
    let target_otk = resolve_otk(coin, &addr_map)?;
    let source = owned
        .into_iter()
        .find(|c| c.p_bytes == target_otk)
        .ok_or_else(|| anyhow::anyhow!("coin {coin} not found among spendable coins"))?;
    let total = source.amount;

    // Compute the output amounts (which must sum to `total`).
    let out_amounts = if let Some(n) = parts {
        split_into_parts(total, n, part_amount)?
    } else {
        let mut amts: Vec<u128> = Vec::with_capacity(amounts.len());
        let mut sum: u128 = 0;
        for a in amounts {
            let v: u128 = a
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid amount (expected base-unit integer): {a}"))?;
            if v == 0 {
                anyhow::bail!("amount must be positive: {a}");
            }
            sum = sum
                .checked_add(v)
                .ok_or_else(|| anyhow::anyhow!("amounts overflow"))?;
            amts.push(v);
        }
        if sum > total {
            anyhow::bail!("amounts sum ({sum}) exceeds coin balance ({total})");
        }
        // Remainder coin so outputs conserve value.
        if total - sum > 0 {
            amts.push(total - sum);
        }
        amts
    };

    let selected = vec![source];
    let (root, depth, inputs) = fetch_inputs(&mut client, &domain, &selected).await?;

    // Every output goes back to this wallet.
    let out_specs: Vec<OutSpec> = out_amounts
        .iter()
        .map(|&amount| OutSpec {
            amount,
            kem_target: w.kem_pk.clone(),
            b_target: w.big_b.clone(),
        })
        .collect();

    submit_spend(&mut client, &w, &domain, &root, depth, &inputs, &out_specs).await?;

    println!(
        "Split submitted: coin of {total} base units → {} coin(s): {:?}",
        out_amounts.len(),
        out_amounts
    );
    Ok(())
}

/// Amounts for `--parts N [--part-amount A]`. With an explicit part amount, N
/// coins of A plus a remainder coin; otherwise N equal coins plus the leftover
/// remainder (mirrors split.go's remainder coin).
fn split_into_parts(total: u128, n: u32, part_amount: Option<&str>) -> anyhow::Result<Vec<u128>> {
    let n = n as u128;
    match part_amount {
        Some(a) => {
            let per: u128 = a
                .parse()
                .map_err(|_| anyhow::anyhow!("invalid --part-amount (base-unit integer): {a}"))?;
            if per == 0 {
                anyhow::bail!("--part-amount must be positive");
            }
            let used = per
                .checked_mul(n)
                .ok_or_else(|| anyhow::anyhow!("part amounts overflow"))?;
            if used > total {
                anyhow::bail!("{n} parts of {per} ({used}) exceed coin balance ({total})");
            }
            let mut amts = vec![per; n as usize];
            if total - used > 0 {
                amts.push(total - used);
            }
            Ok(amts)
        }
        None => {
            let base = total / n;
            if base == 0 {
                anyhow::bail!("coin balance ({total}) too small to split into {n} parts");
            }
            let mut amts = vec![base; n as usize];
            let remainder = total - base * n;
            if remainder > 0 {
                amts.push(remainder);
            }
            Ok(amts)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::split_into_parts;

    /// Every split must conserve value exactly (fee = 0).
    fn assert_conserves(total: u128, amts: &[u128]) {
        assert_eq!(amts.iter().sum::<u128>(), total, "outputs must sum to input");
        assert!(amts.iter().all(|&a| a > 0), "no zero-amount coins");
    }

    #[test]
    fn equal_parts_with_remainder() {
        let amts = split_into_parts(1000, 3, None).unwrap();
        // 3 × 333 + remainder 1.
        assert_eq!(amts, vec![333, 333, 333, 1]);
        assert_conserves(1000, &amts);
    }

    #[test]
    fn equal_parts_exact() {
        let amts = split_into_parts(900, 3, None).unwrap();
        assert_eq!(amts, vec![300, 300, 300]); // no remainder coin
        assert_conserves(900, &amts);
    }

    #[test]
    fn part_amount_with_remainder() {
        let amts = split_into_parts(1000, 2, Some("350")).unwrap();
        assert_eq!(amts, vec![350, 350, 300]);
        assert_conserves(1000, &amts);
    }

    #[test]
    fn part_amount_exact() {
        let amts = split_into_parts(700, 2, Some("350")).unwrap();
        assert_eq!(amts, vec![350, 350]);
        assert_conserves(700, &amts);
    }

    #[test]
    fn rejects_overcommit_and_too_small() {
        assert!(split_into_parts(500, 2, Some("300")).is_err()); // 600 > 500
        assert!(split_into_parts(2, 3, None).is_err()); // base would be 0
    }
}
