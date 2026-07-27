//! `qclient token account` — print the managing account address.
//!
//! Port of `client/cmd/token/account.go`: `poseidon(peerId)` → 32 bytes,
//! printed as `0x…`.

use super::TokenCtx;

pub fn run(tc: &TokenCtx) -> anyhow::Result<()> {
    let addr = quil_crypto::poseidon::hash_bytes_to_32(&tc.peer_id_bytes)
        .map_err(|e| anyhow::anyhow!("poseidon account address: {e}"))?;
    println!("Account: 0x{}", hex::encode(addr));
    Ok(())
}
