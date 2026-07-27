//! `qclient token address` — print the wallet's confidential (lattice)
//! receiving address `hex(kem_pk ‖ wire(B))`, which a sender needs for
//! `token transfer`. `B = a_otk·b` where `b` is the wallet's long-term
//! lattice spend base (persisted at `<config_dir>/q-lattice-spend.key`).

use quil_lattice_ct::membership::MembershipParams;
use quil_lattice_ct::wire;

use super::TokenCtx;

pub fn run(tc: &TokenCtx) -> anyhow::Result<()> {
    let mp = MembershipParams::production(1);
    let a_otk = &mp.a_otk;
    let cols = a_otk.cols;

    let b = super::transfer::load_or_create_b(&tc.config_dir, cols)?;
    let big_b = a_otk.matvec(&b);
    let kem_pk = tc
        .key_manager
        .get_public_key_bytes_by_id("q-onion-key")
        .map_err(|e| anyhow::anyhow!("q-onion-key public: {e}"))?;

    let mut addr = kem_pk;
    addr.extend_from_slice(&wire::encode_polyvec(&big_b));
    println!("Confidential address: 0x{}", hex::encode(&addr));
    Ok(())
}
