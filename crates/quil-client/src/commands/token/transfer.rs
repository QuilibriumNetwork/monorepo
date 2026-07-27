//! `qclient token transfer <RecipientAddress> <Amount>` — a post-quantum
//! confidential transfer.
//!
//! This is the client wiring over the (tested) lattice confidential-transaction
//! pipeline. It does against a live node exactly what
//! `full_wallet_scan_recover_and_spend_end_to_end` proves in-process:
//! `ListDomainCoins` → scan (decapsulate → `owns_ring` → `open_ring_memo`) →
//! `GetCoinSpendWitness` → `build_spend_transaction` → submit the `0x0512`
//! message via `SubmitMessage`.
//!
//! Simplifications (documented, first-cut): `fee = 0`; amounts are raw u128
//! base units; a recipient address is `hex(kem_pk ‖ wire(B))`; the wallet's
//! long-term lattice spend base `b` is persisted at
//! `<config_dir>/q-lattice-spend.key`. A lattice tx is self-authenticating
//! (its spend proof is the authority), so no outer Ed448 signature is used.

use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use quil_execution::token_intrinsic::lattice_ct::{
    build_output_memo, build_spend_transaction, encode_tx_envelope, open_ring_memo,
    production_params, split_output_memo, NewOutput, SpendInput, TxEnvelope,
    TYPE_LATTICE_TRANSACTION,
};
use quil_lattice_ct::membership::MembershipParams;
use quil_lattice_ct::module::PolyVec;
use quil_lattice_ct::stealth::{
    hash_to_short_polyvec, one_time_pubkey_ring, one_time_secret_ring, owns_ring,
};
use quil_lattice_ct::wire;
use quil_types::proto::node::{GetCoinSpendWitnessRequest, ListDomainCoinsRequest, SubmitMessageRequest};

use super::TokenCtx;

/// One spendable coin the wallet has scanned + opened.
struct OwnedCoin {
    p_bytes: Vec<u8>,
    sk: PolyVec,
    amount: u128,
    r_coin: PolyVec,
}

/// A recipient's public lattice address: `(kem_pk, B)`.
struct LatticeAddress {
    kem_pk: Vec<u8>,
    big_b: PolyVec,
}

const SNTRUP761_PK_LEN: usize = 1158;

fn parse_address(hex_str: &str) -> anyhow::Result<LatticeAddress> {
    let raw = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
        .map_err(|e| anyhow::anyhow!("invalid recipient address hex: {e}"))?;
    if raw.len() <= SNTRUP761_PK_LEN {
        anyhow::bail!("recipient address too short");
    }
    let kem_pk = raw[..SNTRUP761_PK_LEN].to_vec();
    let big_b = wire::decode_polyvec(&raw[SNTRUP761_PK_LEN..])
        .map_err(|e| anyhow::anyhow!("invalid recipient B: {e:?}"))?;
    Ok(LatticeAddress { kem_pk, big_b })
}

/// Load the wallet's long-term lattice spend base `b`, generating + persisting
/// it on first use (eta=1 so stealth `sk = offset + b` stays within ETA=2).
pub(super) fn load_or_create_b(config_dir: &std::path::Path, cols: usize) -> anyhow::Result<PolyVec> {
    let path = config_dir.join("q-lattice-spend.key");
    if path.exists() {
        let hex_bytes = std::fs::read_to_string(&path)?;
        let raw = hex::decode(hex_bytes.trim())?;
        return wire::decode_polyvec(&raw).map_err(|e| anyhow::anyhow!("decode b: {e:?}"));
    }
    let mut prg = quil_lattice_ct::arith::SplitMix64::new(rand::random::<u64>());
    let b = PolyVec::sample_short(cols, 1, &mut prg);
    std::fs::write(&path, hex::encode(wire::encode_polyvec(&b)))?;
    println!("Generated wallet lattice spend key at {}", path.display());
    Ok(b)
}

pub async fn run(tc: &TokenCtx, recipient: &str, amount: &str) -> anyhow::Result<()> {
    let transfer_amount: u128 = amount
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid amount (expected a base-unit integer): {amount}"))?;
    let domain = quil_execution::domains::QUIL_TOKEN.to_vec();

    let np = production_params();
    let mp = MembershipParams::production(1);
    let a_otk = &mp.a_otk;
    let cols = a_otk.cols;

    // Wallet keys.
    let b = load_or_create_b(&tc.config_dir, cols)?;
    let big_b = a_otk.matvec(&b);
    let kem_sk = tc
        .key_manager
        .get_secret_key_bytes_by_id("q-onion-key")
        .map_err(|e| anyhow::anyhow!("q-onion-key secret: {e}"))?;
    let kem_pk = tc
        .key_manager
        .get_public_key_bytes_by_id("q-onion-key")
        .map_err(|e| anyhow::anyhow!("q-onion-key public: {e}"))?;

    let recipient_addr = parse_address(recipient)?;
    let mut client = tc.connect().await?;

    // ── Scan the domain's coins for ones we own ──
    let coins = client
        .list_domain_coins(tonic::Request::new(ListDomainCoinsRequest { domain: domain.clone() }))
        .await
        .map_err(|e| anyhow::anyhow!("ListDomainCoins: {e}"))?
        .into_inner()
        .coins;

    let mut owned: Vec<OwnedCoin> = Vec::new();
    for c in &coins {
        if c.memo.is_empty() {
            continue;
        }
        let (kem_ct, ring_memo) = match split_output_memo(&c.memo) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ss = match quil_crypto::sntrup761::decapsulate(&kem_ct, &kem_sk) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let offset = hash_to_short_polyvec(&ss, cols);
        let p = match wire::decode_polyvec(&c.one_time_key) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if owns_ring(a_otk, &offset, &big_b, &p) {
            if let Some((amt, r)) = open_ring_memo(np, &ss, &c.commitment, &ring_memo) {
                owned.push(OwnedCoin {
                    p_bytes: c.one_time_key.clone(),
                    sk: one_time_secret_ring(&offset, &b),
                    amount: amt,
                    r_coin: r,
                });
            }
        }
    }

    if owned.is_empty() {
        anyhow::bail!("no spendable coins found in this account");
    }

    // ── Select inputs covering the amount (fee = 0) ──
    owned.sort_by(|a, b| b.amount.cmp(&a.amount));
    let mut selected: Vec<&OwnedCoin> = Vec::new();
    let mut total: u128 = 0;
    for c in &owned {
        if total >= transfer_amount {
            break;
        }
        selected.push(c);
        total += c.amount;
    }
    if total < transfer_amount {
        anyhow::bail!(
            "insufficient balance: have {total}, need {transfer_amount} (base units)"
        );
    }

    // ── Fetch accumulator witnesses for the selected coins ──
    let otks: Vec<Vec<u8>> = selected.iter().map(|c| c.p_bytes.clone()).collect();
    let witness = client
        .get_coin_spend_witness(tonic::Request::new(GetCoinSpendWitnessRequest {
            domain: domain.clone(),
            one_time_keys: otks.clone(),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("GetCoinSpendWitness: {e}"))?
        .into_inner();
    let depth = witness.depth as usize;
    let root = witness.root;

    let mut inputs: Vec<SpendInput> = Vec::with_capacity(selected.len());
    for c in &selected {
        let w = witness
            .witnesses
            .iter()
            .find(|w| w.one_time_key == c.p_bytes && w.found)
            .ok_or_else(|| anyhow::anyhow!("node has no witness for a selected coin"))?;
        inputs.push(SpendInput {
            sk: c.sk.clone(),
            amount: c.amount,
            r_coin: c.r_coin.clone(),
            leaf_index: w.leaf_index as usize,
            auth_path: w.auth_path.clone(),
        });
    }

    // ── Build outputs: recipient + change-to-self ──
    // Each output: encapsulate to its KEM pubkey → (ss, kem_ct); derive its
    // one-time key P; the (ss, kem_ct) feed the per-output memo after build.
    struct OutMeta {
        kem_ct: Vec<u8>,
        ss: Vec<u8>,
    }
    let mut outputs: Vec<NewOutput> = Vec::new();
    let mut out_meta: Vec<OutMeta> = Vec::new();

    let mut push_output = |amount: u128, kem_target: &[u8], b_target: &PolyVec, outs: &mut Vec<NewOutput>, meta: &mut Vec<OutMeta>| -> anyhow::Result<()> {
        let (ss, kem_ct) = quil_crypto::sntrup761::encapsulate(kem_target)
            .map_err(|e| anyhow::anyhow!("encapsulate: {e}"))?;
        let offset = hash_to_short_polyvec(&ss, cols);
        let p_out = one_time_pubkey_ring(a_otk, &offset, b_target);
        outs.push(NewOutput { amount, recipient_otk: wire::encode_polyvec(&p_out) });
        meta.push(OutMeta { kem_ct, ss });
        Ok(())
    };

    push_output(transfer_amount, &recipient_addr.kem_pk, &recipient_addr.big_b, &mut outputs, &mut out_meta)?;
    let change = total - transfer_amount;
    if change > 0 {
        push_output(change, &kem_pk, &big_b, &mut outputs, &mut out_meta)?;
    }

    // ── Build the spend + attach per-output memos ──
    let seed = rand::random::<u64>();
    let tx = build_spend_transaction(np, &root, depth, &domain, &inputs, &outputs, 0, seed)
        .map_err(|e| anyhow::anyhow!("build spend transaction: {e}"))?;

    let mut env = TxEnvelope::from_built(&tx);
    env.output_memos = (0..outputs.len())
        .map(|i| {
            let r_out = wire::decode_polyvec(&tx.output_rand[i])
                .map_err(|e| anyhow::anyhow!("decode output rand: {e:?}"))?;
            Ok(build_output_memo(&out_meta[i].kem_ct, outputs[i].amount, &r_out, &out_meta[i].ss))
        })
        .collect::<anyhow::Result<_>>()?;

    // ── Frame + submit: [0x0512][envelope] → MessageRequest → MessageBundle ──
    let mut msg = TYPE_LATTICE_TRANSACTION.to_be_bytes().to_vec();
    msg.extend_from_slice(&encode_tx_envelope(&env));
    let req = CanonicalMessageRequest::wrap(msg)
        .map_err(|e| anyhow::anyhow!("wrap message request: {e}"))?;
    let bundle = CanonicalMessageBundle {
        requests: vec![Some(req)],
        timestamp: crate::send::now_millis(),
    };
    let data = bundle
        .to_canonical_bytes()
        .map_err(|e| anyhow::anyhow!("canonicalize bundle: {e}"))?;

    client
        .submit_message(tonic::Request::new(SubmitMessageRequest { data }))
        .await
        .map_err(|e| anyhow::anyhow!("SubmitMessage: {e}"))?;

    println!(
        "Transfer submitted: {transfer_amount} to recipient (change {change}), \
         {} input(s)",
        inputs.len()
    );
    Ok(())
}
