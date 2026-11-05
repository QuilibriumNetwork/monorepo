//! Read-only prover rewards, independent of the application's wallet coin scan.

use super::{wallet::RecipientWallet, TokenCtx};
use quil_types::proto::node::{
    node_service_client::NodeServiceClient, GetProverRewardWitnessRequest,
};
use tonic::transport::Channel;

/// The claimable rewards line, and why the reward read failed, if it did.
pub(super) async fn claimable_rewards(tc: &TokenCtx, verbose: bool) -> (String, Option<String>) {
    // Rewards are GLOBAL state held by the configured node. --read-rpc may
    // name a worker holding application coins, so it is not used for this read.
    let result = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let public = tc.key_manager.get_public_key_bytes_by_id("q-prover-key")?;
        let client = tc.connect_submit().await?;
        read_claimable_rewards(client, &public).await
    })
    .await
    .unwrap_or_else(|_| Err(anyhow::anyhow!("reward query timed out")));
    let failed = result.as_ref().err().map(reason);
    (format_claimable_rewards(result, verbose), failed)
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

/// The rewards line; `verbose` adds the exact amount and the witness frame.
/// A failure's reason ends the command's error instead (see [`incomplete`]).
fn format_claimable_rewards(result: anyhow::Result<Option<(u128, u64)>>, verbose: bool) -> String {
    match result {
        Ok(Some((value, frame))) if verbose => format!(
            "Claimable rewards: {} QUIL ({value} base units; witness cites global frame {frame}), mint to claim",
            quil_amount(value)
        ),
        Ok(Some((value, _))) => format!("Claimable rewards: {} QUIL, mint to claim", quil_brief(value)),
        Ok(None) if verbose => "Claimable rewards: none (no claimable reward witness returned)".into(),
        Ok(None) => "Claimable rewards: none".into(),
        Err(_) => "Claimable rewards: unavailable".into(),
    }
}

/// The `token balance` line for this identity's unshielded legacy coins:
/// `(total, unshielded, shielded)`, or `None` without an Ed448 identity.
/// `verbose` adds base units, the shielded count and why there are none.
pub(super) fn format_legacy_coins(
    result: &anyhow::Result<Option<(u128, usize, usize)>>,
    verbose: bool,
) -> String {
    const NONE: &str = "Unshielded legacy coins: none";
    match result {
        // The listing answered with nothing: distinct from no answer.
        Ok(Some((_, 0, 0))) if verbose => {
            format!("{NONE} (the listing has no coin under this identity's key or peer-id owner)")
        }
        Ok(Some((_, 0, shielded))) if verbose => {
            format!("{NONE} left ({shielded} already shielded)")
        }
        Ok(Some((_, 0, _))) => NONE.into(),
        Ok(Some((total, unshielded, shielded))) if verbose => format!(
            "Unshielded legacy coins: {} QUIL ({total} base units) in {} ({shielded} already shielded), shield to spend",
            quil_amount(*total),
            coins(*unshielded)
        ),
        Ok(Some((total, unshielded, _))) => format!(
            "Unshielded legacy coins: {} QUIL in {}, shield to spend",
            quil_brief(*total),
            coins(*unshielded)
        ),
        Ok(None) if verbose => format!("{NONE} (this node has no Ed448 identity)"),
        Ok(None) => NONE.into(),
        Err(_) => "Unshielded legacy coins: unavailable".into(),
    }
}

/// The `token balance` line for confidential coins: `(total, coins)`, or
/// `None` when the node answers that the application has no coin root yet.
/// `verbose` adds base units, where the count comes from and why there are
/// none.
pub(super) fn format_confidential_coins(
    result: &anyhow::Result<Option<(u128, usize)>>,
    quil: bool,
    verbose: bool,
) -> String {
    const UNSPENT: &str = "reported unspent by the configured node (not a finalized balance)";
    match result {
        Ok(Some((total, count))) if quil && verbose => format!(
            "Confidential QUIL coins: {} QUIL ({total} base units) in {} {UNSPENT}",
            quil_amount(*total),
            coins(*count)
        ),
        Ok(Some((total, count))) if quil => format!(
            "Confidential QUIL coins: {} QUIL in {}",
            quil_brief(*total),
            coins(*count)
        ),
        Ok(Some((total, count))) if verbose => {
            format!(
                "Confidential coins: {total} base units in {} {UNSPENT}",
                coins(*count)
            )
        }
        Ok(Some((total, count))) => {
            format!(
                "Confidential coins: {total} base units in {}",
                coins(*count)
            )
        }
        Ok(None) if quil && verbose => {
            "Confidential QUIL coins: none (no QUIL root published on the network yet)".into()
        }
        Ok(None) if quil => "Confidential QUIL coins: none".into(),
        Ok(None) if verbose => {
            "Confidential coins: none (no root published in this application yet)".into()
        }
        Ok(None) => "Confidential coins: none".into(),
        Err(_) => "Confidential coins: unavailable".into(),
    }
}

/// `count` coins, singular for one.
fn coins(count: usize) -> String {
    format!("{count} coin{}", if count == 1 { "" } else { "s" })
}

/// The error ending a `token balance` some of whose reads failed: each
/// distinct reason once, after the reads it failed, the lines having said
/// only "unavailable".
pub(super) fn incomplete(failed: &[(&str, String)]) -> String {
    let mut reasons: Vec<(Vec<&str>, &str)> = Vec::new();
    for (read, why) in failed {
        let (read, why): (&str, &str) = (read, why);
        match reasons.iter().position(|(_, known)| *known == why) {
            Some(at) => reasons[at].0.push(read),
            None => reasons.push((vec![read], why)),
        }
    }
    let parts: Vec<String> = reasons
        .iter()
        .map(|(reads, why)| format!("{} unavailable: {why}", reads.join(", ")))
        .collect();
    format!("balance incomplete: {}", parts.join("; "))
}

/// `units` of QUIL as an exact decimal QUIL amount (12 decimals).
pub(crate) fn quil_amount(units: u128) -> String {
    crate::util::float_string_12(
        &num_bigint::BigInt::from(units),
        &crate::util::conversion_factor(),
    )
}

/// `units` of QUIL as an operator reads it: rounded to six decimals,
/// trailing zeros dropped. A non-zero amount that would round to zero
/// shows exactly; `-v` shows every amount exactly ([`quil_amount`]).
pub(crate) fn quil_brief(units: u128) -> String {
    const SCALE: u128 = 1_000_000;
    let factor = u128::from(crate::util::UNITS_PER_QUIL);
    let (mut whole, rest) = (units / factor, units % factor);
    // Half up: rest < factor, so this cannot overflow.
    let mut fraction = (rest * SCALE * 2 + factor) / (factor * 2);
    if fraction == SCALE {
        (whole, fraction) = (whole + 1, 0);
    }
    if whole == 0 && fraction == 0 && units > 0 {
        return quil_amount(units).trim_end_matches('0').to_string();
    }
    let text = format!("{whole}.{fraction:06}");
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// A refusal's own message rather than tonic's whole status dump.
pub(super) fn reason(error: &anyhow::Error) -> String {
    match error.downcast_ref::<tonic::Status>() {
        Some(status) => status.message().to_string(),
        None => format!("{error:#}"),
    }
}

#[cfg(test)]
#[path = "balance_tests.rs"]
pub(crate) mod tests;
