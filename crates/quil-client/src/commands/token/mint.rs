//! `qclient token mint [<RecipientAddress>]` — claim this prover's PoMW reward
//! balance as new confidential QUIL coins.
//!
//! Lattice port of `client/cmd/token/mint.go` (the Go proof-of-work proof is
//! replaced by the node-provided forest reward witness). The node's
//! `GetProverRewardWitness` RPC returns a membership proof of this prover's
//! `reward:ProverReward` vertex + the claimable `value`; the client builds a
//! `MintEnvelope` (0x0513) that mints exactly that value into a coin.

use quil_execution::token_intrinsic::lattice_ct::{
    build_mint_transaction, build_output_memo, encode_mint_envelope, mint_auth_message,
    tx_challenge, LatticeMintInput, MintEnvelope, NewOutput, TYPE_LATTICE_MINT,
};
use quil_lattice_ct::stealth::{hash_to_short_polyvec, one_time_pubkey_ring};
use quil_lattice_ct::wire;
use quil_types::crypto::Signer;
use quil_types::proto::node::GetProverRewardWitnessRequest;

use super::balance::claimable_reward_value;
use super::lattice::{parse_address, submit_lattice_message, Wallet};
use super::TokenCtx;

pub async fn run(tc: &TokenCtx, recipient: Option<&str>) -> anyhow::Result<()> {
    let domain = quil_execution::domains::QUIL_TOKEN.to_vec();
    let w = Wallet::load(tc)?;
    let mut client = tc.connect().await?;

    // This prover's address = poseidon(q-prover-key Falcon pubkey).
    let owner = quil_crypto::poseidon::hash_bytes_to_32(&w.falcon_pk)
        .map_err(|e| anyhow::anyhow!("prover address: {e}"))?
        .to_vec();

    // Fetch the reward witness (forest membership proof + claimable value).
    let resp = client
        .get_prover_reward_witness(tonic::Request::new(GetProverRewardWitnessRequest {
            domain: domain.clone(),
            owner_prover_address: owner.clone(),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("GetProverRewardWitness: {e}"))?
        .into_inner();
    if !resp.found {
        anyhow::bail!("no claimable prover reward found for this wallet");
    }
    let value = claimable_reward_value(resp.found, &resp.value)?
        .ok_or_else(|| anyhow::anyhow!("no claimable prover reward found for this wallet"))?;
    if value == 0 {
        anyhow::bail!("prover reward balance is zero");
    }

    // Recipient: self (change-style output) by default, else a transfer address.
    let (kem_target, b_target) = match recipient {
        None => (w.kem_pk.clone(), w.big_b.clone()),
        Some(addr) => {
            let a = parse_address(addr)?;
            (a.kem_pk, a.big_b)
        }
    };

    // One output coin of exactly `value` (mint conservation is Σ outputs = value).
    let (ss, kem_ct) = quil_crypto::sntrup761::encapsulate(&kem_target)
        .map_err(|e| anyhow::anyhow!("encapsulate: {e}"))?;
    let offset = hash_to_short_polyvec(&ss, w.cols);
    let p_out = one_time_pubkey_ring(&w.mp.a_otk, &offset, &b_target);
    let outputs = vec![NewOutput { amount: value, recipient_otk: wire::encode_polyvec(&p_out) }];

    let seed = rand::random::<u64>();
    let built = build_mint_transaction(w.np, value, &outputs, seed)
        .map_err(|e| anyhow::anyhow!("build mint transaction: {e}"))?;
    let r_out = wire::decode_polyvec(&built.output_rand[0])
        .map_err(|e| anyhow::anyhow!("decode output rand: {e:?}"))?;
    let memo = build_output_memo(&kem_ct, value, &r_out, &ss);

    // Authorization: Falcon signature over mint_auth_message(value, mu), where
    // mu binds the outputs (tx challenge).
    let mu = tx_challenge(&domain, &built.output_commitments, value);
    let signer = w.falcon_signer();
    let falcon_sig = signer
        .sign_with_domain(&mint_auth_message(value, &mu), &domain)
        .map_err(|e| anyhow::anyhow!("mint auth sign: {e}"))?;

    let input = LatticeMintInput {
        value,
        owner_prover_address: owner,
        falcon_pubkey: w.falcon_pk.clone(),
        falcon_sig,
        forest_proof: resp.forest_proof,
    };
    let env = MintEnvelope {
        cited_frame: resp.cited_frame,
        inputs: vec![input],
        output_commitments: built.output_commitments,
        output_range_proofs: Vec::new(),
        output_otks: built.new_coins.iter().map(|(p, _)| p.clone()).collect(),
        balance_proof: built.balance_proof,
        output_memos: vec![memo],
    };
    submit_lattice_message(&mut client, TYPE_LATTICE_MINT, &encode_mint_envelope(&env)).await?;

    println!(
        "Mint submitted: {value} base units claimed from the prover reward (cited frame {})",
        resp.cited_frame
    );
    Ok(())
}
