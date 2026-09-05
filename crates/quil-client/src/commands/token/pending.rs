//! Confidential escrow (pending transfer) commands: create an acceptable
//! transfer, and `accept` / `reject` (claim / refund) one.
//!
//! An escrow locks value for a recipient (the `to` Falcon key) with a refund
//! path back to the sender after `expiration`. The sender's memo KEM-encrypts
//! `(amount, escrow_r)` to both parties so either can recover + claim. Built on
//! the lattice `build_pending_create` (0x0514) / `build_pending_claim` (0x0515)
//! primitives via the shared machinery in [`super::lattice`].

use quil_execution::token_intrinsic::lattice_ct::{
    build_escrow_memo, build_output_memo, build_pending_claim, build_spend_transaction,
    encode_pending_claim, encode_pending_create, open_escrow_memo, NewOutput, PendingCreateEnvelope,
    TYPE_LATTICE_PENDING, TYPE_LATTICE_PENDING_CLAIM,
};
use quil_lattice_ct::stealth::{hash_to_short_polyvec, one_time_pubkey_ring};
use quil_lattice_ct::wire;
use quil_types::proto::node::GetNodeInfoRequest;

use super::lattice::{
    fetch_inputs, list_escrows, parse_pending_address, scan_owned_coins, select_to_cover,
    submit_lattice_message, Wallet,
};
use super::TokenCtx;

/// Default escrow lifetime if `--expiration` is omitted: ~1 day at 10s/frame,
/// measured from the current global head.
const DEFAULT_EXPIRATION_FRAMES: u64 = 8640;

/// `token pending-transfer <ToPendingAddress> <Amount> [--expiration N]`.
pub async fn create(
    tc: &TokenCtx,
    recipient: &str,
    amount: &str,
    expiration: Option<u64>,
) -> anyhow::Result<()> {
    let escrow_amount: u128 = amount
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid amount (expected base-unit integer): {amount}"))?;
    let domain = quil_execution::domains::QUIL_TOKEN.to_vec();
    let w = Wallet::load(tc)?;
    let to = parse_pending_address(recipient)?;
    let mut client = tc.connect().await?;

    // Resolve the expiration frame (default = head + ~1 day).
    let expiration = match expiration {
        Some(e) => e,
        None => {
            let head = client
                .get_node_info(tonic::Request::new(GetNodeInfoRequest::default()))
                .await
                .map_err(|e| anyhow::anyhow!("get node info: {e}"))?
                .into_inner()
                .last_global_head_frame;
            head + DEFAULT_EXPIRATION_FRAMES
        }
    };

    let owned = scan_owned_coins(&mut client, &domain, &w).await?;
    if owned.is_empty() {
        anyhow::bail!("no spendable coins found in this account");
    }
    let (selected, total) = select_to_cover(owned, escrow_amount)?;
    let (root, depth, inputs) = fetch_inputs(&mut client, &domain, &selected).await?;

    // Outputs: escrow (index 0, no OTK) + change-to-self (index 1, if any).
    let change = total - escrow_amount;
    let mut outputs = vec![NewOutput { amount: escrow_amount, recipient_otk: Vec::new() }];
    let mut change_kem: Option<(Vec<u8>, Vec<u8>)> = None; // (kem_ct, ss) for the change memo
    if change > 0 {
        let (ss, kem_ct) = quil_crypto::sntrup761::encapsulate(&w.kem_pk)
            .map_err(|e| anyhow::anyhow!("encapsulate change: {e}"))?;
        let offset = hash_to_short_polyvec(&ss, w.cols);
        let p = one_time_pubkey_ring(&w.mp.a_otk, &offset, &w.big_b);
        outputs.push(NewOutput { amount: change, recipient_otk: wire::encode_polyvec(&p) });
        change_kem = Some((kem_ct, ss));
    }

    let seed = rand::random::<u64>();
    let built = build_spend_transaction(w.np, &root, depth, &domain, &inputs, &outputs, 0, seed)
        .map_err(|e| anyhow::anyhow!("build escrow transaction: {e}"))?;

    let escrow_r = wire::decode_polyvec(&built.output_rand[0])
        .map_err(|e| anyhow::anyhow!("decode escrow rand: {e:?}"))?;
    // Dual-party memo: either the `to` party or the sender (refund) can open it.
    let memo = build_escrow_memo(&to.kem_pk, &w.kem_pk, escrow_amount, &escrow_r)?;

    let (change_commitments, change_otks, change_memos) = if change > 0 {
        let (kem_ct, ss) = change_kem.unwrap();
        let change_r = wire::decode_polyvec(&built.output_rand[1])
            .map_err(|e| anyhow::anyhow!("decode change rand: {e:?}"))?;
        let change_memo = build_output_memo(&kem_ct, change, &change_r, &ss);
        (
            vec![built.output_commitments[1].clone()],
            vec![outputs[1].recipient_otk.clone()],
            vec![change_memo],
        )
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };

    // Packed per-limb ranges: [0] = escrow, [1..] = change (from the built tx).
    let escrow_range_proof = built.output_range_proofs.first().cloned().unwrap_or_default();
    let change_range_proofs: Vec<Vec<u8>> =
        built.output_range_proofs.iter().skip(1).cloned().collect();
    let env = PendingCreateEnvelope {
        input_spend_proofs: built.input_spend_proofs,
        escrow_commitment: built.output_commitments[0].clone(),
        escrow_range_proof,
        balance_proof: built.balance_proof,
        fee: 0,
        to_key: to.falcon_pk,
        refund_key: w.falcon_pk.clone(),
        expiration,
        memo,
        change_commitments,
        change_otks,
        change_memos,
        change_range_proofs,
    };
    submit_lattice_message(&mut client, TYPE_LATTICE_PENDING, &encode_pending_create(&env)).await?;

    println!(
        "Escrow created: {escrow_amount} locked for recipient (change {change}), refundable at frame {expiration}"
    );
    Ok(())
}

/// `token accept <Escrow>` (`is_to = true`) / `token reject <Escrow>` (`is_to = false`).
pub async fn claim(tc: &TokenCtx, escrow_id: &str, is_to: bool) -> anyhow::Result<()> {
    let action = if is_to { "Accept" } else { "Reject" };
    let domain = quil_execution::domains::QUIL_TOKEN.to_vec();
    let w = Wallet::load(tc)?;
    let mut client = tc.connect().await?;

    let want = hex::decode(escrow_id.strip_prefix("0x").unwrap_or(escrow_id))
        .map_err(|e| anyhow::anyhow!("invalid escrow address hex: {e}"))?;
    let escrows = list_escrows(&mut client, &domain).await?;
    let esc = escrows
        .iter()
        .find(|e| e.address == want)
        .ok_or_else(|| anyhow::anyhow!("escrow 0x{} not found", hex::encode(&want)))?;

    // Authorization: our Falcon key must be the escrow's to (accept) / refund (reject) key.
    let expected_key = if is_to { &esc.to_key } else { &esc.refund_key };
    if *expected_key != w.falcon_pk {
        anyhow::bail!(
            "this wallet is not the {} party for escrow 0x{}",
            if is_to { "recipient" } else { "refund" },
            hex::encode(&esc.address)
        );
    }

    // Recover (amount, escrow_r) from the memo.
    let (amount, escrow_r) = open_escrow_memo(w.np, &w.kem_sk, &esc.cv, &esc.memo)
        .ok_or_else(|| anyhow::anyhow!("cannot open escrow memo (not addressed to this wallet?)"))?;

    // New coin back to self, with a memo so it can later be scanned + spent.
    let (ss, kem_ct) = quil_crypto::sntrup761::encapsulate(&w.kem_pk)
        .map_err(|e| anyhow::anyhow!("encapsulate claim: {e}"))?;
    let offset = hash_to_short_polyvec(&ss, w.cols);
    let claim_otk = wire::encode_polyvec(&one_time_pubkey_ring(&w.mp.a_otk, &offset, &w.big_b));

    let mut esc_addr = [0u8; 32];
    if esc.address.len() != 32 {
        anyhow::bail!("escrow address is not 32 bytes");
    }
    esc_addr.copy_from_slice(&esc.address);

    let signer = w.falcon_signer();
    let seed = rand::random::<u64>();
    let (mut env, r_out) = build_pending_claim(
        w.np, &domain, esc_addr, amount, &escrow_r, is_to, &signer, claim_otk, seed,
    )
    .map_err(|e| anyhow::anyhow!("build claim: {e}"))?;
    env.output_memo = build_output_memo(&kem_ct, amount, &r_out, &ss);

    submit_lattice_message(&mut client, TYPE_LATTICE_PENDING_CLAIM, &encode_pending_claim(&env)).await?;

    println!(
        "{action} submitted: {amount} claimed from escrow 0x{}",
        hex::encode(&esc.address)
    );
    if !is_to {
        println!("(refund is only applied by the node once frame ≥ {})", esc.expiration);
    }
    Ok(())
}
