//! `qclient token legacy` — this identity's legacy (pre-2.1) coins.
//!
//! Legacy coins are transparent: owner, amount and origin are public, so the
//! node is asked for them by owner. A shield accepts either owner form a key
//! has, `poseidon(Ed448 public key)` or `poseidon(peer-id multihash)`, so
//! both are listed. Only archives keep the owner index; the configured node
//! forwards there.

use super::TokenCtx;
use quil_types::proto::global::ListLegacyCoinsRequest;

/// The two owner addresses of this node's Ed448 identity. The configured key
/// is the 57-byte seed then the 57-byte public key, in hex; only the public
/// half is decoded.
fn owner_addresses(tc: &TokenCtx) -> anyhow::Result<Vec<[u8; 32]>> {
    let no_identity = || anyhow::anyhow!("this node has no Ed448 identity, so it holds no legacy coins");
    let key = &tc.node_config.p2p.peer_priv_key;
    anyhow::ensure!(key.len() == 228, no_identity());
    let public = hex::decode(&key[114..]).map_err(|_| no_identity())?;
    let public = public.as_slice();
    let by_key = quil_crypto::poseidon::hash_bytes_to_32(public)
        .map_err(|e| anyhow::anyhow!("owner address: {e}"))?;
    let by_peer = quil_crypto::poseidon::hash_bytes_to_32(&quil_crypto::peer_id_multihash_from_ed448_pubkey(public))
        .map_err(|e| anyhow::anyhow!("owner address: {e}"))?;
    let mut owners = vec![by_key, by_peer];
    owners.dedup();
    Ok(owners)
}

/// Every legacy coin of this identity, both owner forms, as
/// `(address, amount, shielded)`.
pub(crate) async fn list(
    tc: &TokenCtx,
    client: &quil_types::proto::node::node_service_client::NodeServiceClient<tonic::transport::Channel>,
    application: &[u8; 32],
) -> anyhow::Result<Vec<([u8; 32], u128, bool)>> {
    let mut coins = Vec::new();
    for owner in owner_addresses(tc)? {
        let mut after: Vec<u8> = Vec::new();
        loop {
            let page = match client.clone()
                .list_legacy_coins(ListLegacyCoinsRequest { domain: application.to_vec(), owner: owner.to_vec(), after: after.clone() })
                .await
            {
                Ok(page) => page.into_inner(),
                Err(status) if status.code() == tonic::Code::Unimplemented => {
                    anyhow::bail!("the configured node cannot list legacy coins; upgrade it")
                }
                Err(status) => return Err(anyhow::anyhow!("legacy coins: {}", status.message())),
            };
            for coin in &page.coins {
                let amount = u128::from_le_bytes(coin.amount.as_slice().try_into()
                    .map_err(|_| anyhow::anyhow!("malformed legacy coin amount"))?);
                let address: [u8; 32] = coin.address.as_slice().try_into()
                    .map_err(|_| anyhow::anyhow!("malformed legacy coin address"))?;
                anyhow::ensure!(coin.address > after, "legacy coins out of order");
                coins.push((address, amount, coin.shielded));
                after = coin.address.clone();
            }
            if !page.has_more {
                break;
            }
            anyhow::ensure!(!page.coins.is_empty(), "legacy coin listing did not advance");
        }
    }
    Ok(coins)
}

pub async fn run(tc: &TokenCtx, application: &[u8; 32]) -> anyhow::Result<()> {
    let client = tc.connect().await?;
    let (mut unshielded_total, mut unshielded, mut shielded) = (0u128, 0usize, 0usize);
    for (address, amount, is_shielded) in list(tc, &client, application).await? {
        println!("0x{} {}{}", hex::encode(address), amount, if is_shielded { " (shielded)" } else { "" });
        if is_shielded {
            shielded += 1;
        } else {
            unshielded += 1;
            unshielded_total = unshielded_total.checked_add(amount)
                .ok_or_else(|| anyhow::anyhow!("legacy total overflows u128"))?;
        }
    }
    println!("{unshielded_total} base units across {unshielded} unshielded legacy coins ({shielded} already shielded)");
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn both_owner_forms_match_what_a_shield_accepts() {
        // The same derivations `shield::check_source` compares against.
        let public = [5u8; 57];
        let by_key = quil_crypto::poseidon::hash_bytes_to_32(&public).unwrap();
        let by_peer = quil_crypto::poseidon::hash_bytes_to_32(&quil_crypto::peer_id_multihash_from_ed448_pubkey(&public)).unwrap();
        assert_ne!(by_key, by_peer);
    }
}
