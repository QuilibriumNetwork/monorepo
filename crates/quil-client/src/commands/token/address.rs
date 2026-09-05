//! `qclient token confidential-address` — print this wallet's receiving
//! addresses:
//!   * the **confidential** (transfer) address
//!     `hex(VERSION ‖ FINGERPRINT ‖ kem_pk ‖ wire(B))`, used by `token transfer`.
//!     The parameter FINGERPRINT makes a cross-parameter (e.g. different modulus
//!     `q`) send fail closed — a coin minted for a mismatched address would be
//!     unspendable, so `parse_address` refuses it; and
//!   * the **escrow/pending** address `hex(kem_pk ‖ falcon_pk)`, used by
//!     `token pending-transfer` (the sender needs the recipient's Falcon claim
//!     key as well as its KEM key). This carries no `R_q` public key, so it needs
//!     no parameter fingerprint.

use super::lattice::{encode_address, Wallet};
use super::TokenCtx;

pub fn run(tc: &TokenCtx) -> anyhow::Result<()> {
    let w = Wallet::load(tc)?;

    let transfer_addr = encode_address(&w.kem_pk, &w.big_b);
    println!("Confidential address: 0x{}", hex::encode(&transfer_addr));

    println!("Escrow (pending) address: 0x{}", hex::encode(w.pending_address()));
    Ok(())
}
