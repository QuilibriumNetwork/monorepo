//! `qclient token confidential-address` — print this wallet's receiving
//! addresses:
//!   * the **confidential** (transfer) address `hex(kem_pk ‖ wire(B))`, used by
//!     `token transfer`; and
//!   * the **escrow/pending** address `hex(kem_pk ‖ falcon_pk)`, used by
//!     `token pending-transfer` (the sender needs the recipient's Falcon claim
//!     key as well as its KEM key).

use quil_lattice_ct::wire;

use super::lattice::Wallet;
use super::TokenCtx;

pub fn run(tc: &TokenCtx) -> anyhow::Result<()> {
    let w = Wallet::load(tc)?;

    let mut transfer_addr = w.kem_pk.clone();
    transfer_addr.extend_from_slice(&wire::encode_polyvec(&w.big_b));
    println!("Confidential address: 0x{}", hex::encode(&transfer_addr));

    println!("Escrow (pending) address: 0x{}", hex::encode(w.pending_address()));
    Ok(())
}
