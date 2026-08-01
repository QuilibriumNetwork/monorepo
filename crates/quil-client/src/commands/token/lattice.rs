//! Shared client-side machinery for lattice confidential-transaction spends
//! (`transfer`, `split`, `merge`). Factored out of `transfer.rs` so every
//! spend command reuses the same scan → select → witness → build → submit
//! pipeline that `full_wallet_scan_recover_and_spend_end_to_end` proves.

use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use quil_execution::token_intrinsic::lattice_ct::{
    build_output_memo, build_spend_transaction, encode_tx_envelope, open_ring_memo,
    production_params, split_output_memo, NetworkParams, NewOutput, SpendInput, TxEnvelope,
    TYPE_LATTICE_TRANSACTION,
};
use quil_lattice_ct::membership::MembershipParams;
use quil_lattice_ct::module::PolyVec;
use quil_lattice_ct::stealth::{
    hash_to_short_polyvec, one_time_pubkey_ring, one_time_secret_ring, owns_ring,
};
use quil_lattice_ct::wire;
use quil_types::proto::node::node_service_client::NodeServiceClient;
use quil_types::proto::node::{
    GetCoinSpendWitnessRequest, GetTokensByAccountRequest, ListDomainCoinsRequest,
    SubmitMessageRequest,
};
use std::collections::HashMap;
use tonic::transport::Channel;

use super::TokenCtx;

type Client = NodeServiceClient<Channel>;

const SNTRUP761_PK_LEN: usize = 1158;

/// One spendable coin the wallet has scanned + opened.
pub struct OwnedCoin {
    pub p_bytes: Vec<u8>,
    pub sk: PolyVec,
    pub amount: u128,
    pub r_coin: PolyVec,
}

/// A recipient's public lattice address: `(kem_pk, B)`.
pub struct LatticeAddress {
    pub kem_pk: Vec<u8>,
    pub big_b: PolyVec,
}

/// Parse a `hex(kem_pk ‖ wire(B))` recipient address.
pub fn parse_address(hex_str: &str) -> anyhow::Result<LatticeAddress> {
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
pub fn load_or_create_b(config_dir: &std::path::Path, cols: usize) -> anyhow::Result<PolyVec> {
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

/// The wallet's lattice keys + params, gathered once per command.
pub struct Wallet {
    pub np: &'static NetworkParams,
    pub mp: MembershipParams,
    pub cols: usize,
    pub b: PolyVec,
    pub big_b: PolyVec,
    pub kem_sk: Vec<u8>,
    pub kem_pk: Vec<u8>,
    /// `q-prover-key` Falcon keypair bytes — the escrow claim authority.
    pub falcon_sk: Vec<u8>,
    pub falcon_pk: Vec<u8>,
}

impl Wallet {
    pub fn load(tc: &TokenCtx) -> anyhow::Result<Self> {
        let np = production_params();
        let mp = MembershipParams::production(1);
        let cols = mp.a_otk.cols;
        let b = load_or_create_b(&tc.config_dir, cols)?;
        let big_b = mp.a_otk.matvec(&b);
        let km = &tc.key_manager;
        let kem_sk = km
            .get_secret_key_bytes_by_id("q-onion-key")
            .map_err(|e| anyhow::anyhow!("q-onion-key secret: {e}"))?;
        let kem_pk = km
            .get_public_key_bytes_by_id("q-onion-key")
            .map_err(|e| anyhow::anyhow!("q-onion-key public: {e}"))?;
        let falcon_sk = km
            .get_secret_key_bytes_by_id("q-prover-key")
            .map_err(|e| anyhow::anyhow!("q-prover-key secret: {e}"))?;
        let falcon_pk = km
            .get_public_key_bytes_by_id("q-prover-key")
            .map_err(|e| anyhow::anyhow!("q-prover-key public: {e}"))?;
        Ok(Wallet { np, mp, cols, b, big_b, kem_sk, kem_pk, falcon_sk, falcon_pk })
    }

    /// The `q-prover-key` Falcon signer (escrow claim authority).
    pub fn falcon_signer(&self) -> quil_crypto::FalconSigner {
        quil_crypto::FalconSigner::from_bytes(&self.falcon_sk, &self.falcon_pk)
    }

    /// This wallet's escrow/pending receiving address: `hex(kem_pk ‖ falcon_pk)`.
    pub fn pending_address(&self) -> Vec<u8> {
        let mut a = self.kem_pk.clone();
        a.extend_from_slice(&self.falcon_pk);
        a
    }
}

/// A recipient's escrow address: KEM pubkey (for the memo) + Falcon pubkey (the
/// claim key). Parsed from `hex(kem_pk ‖ falcon_pk)`.
pub struct PendingAddress {
    pub kem_pk: Vec<u8>,
    pub falcon_pk: Vec<u8>,
}

pub fn parse_pending_address(hex_str: &str) -> anyhow::Result<PendingAddress> {
    let raw = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
        .map_err(|e| anyhow::anyhow!("invalid pending address hex: {e}"))?;
    if raw.len() <= SNTRUP761_PK_LEN {
        anyhow::bail!("pending address too short (expected kem_pk ‖ falcon_pk)");
    }
    let kem_pk = raw[..SNTRUP761_PK_LEN].to_vec();
    let falcon_pk = raw[SNTRUP761_PK_LEN..].to_vec();
    Ok(PendingAddress { kem_pk, falcon_pk })
}

/// List a domain's escrows (pending vertices) via the node RPC.
pub async fn list_escrows(
    client: &mut Client,
    domain: &[u8],
) -> anyhow::Result<Vec<quil_types::proto::node::DomainEscrow>> {
    let resp = client
        .list_domain_escrows(tonic::Request::new(
            quil_types::proto::node::ListDomainEscrowsRequest { domain: domain.to_vec() },
        ))
        .await
        .map_err(|e| anyhow::anyhow!("ListDomainEscrows: {e}"))?
        .into_inner();
    Ok(resp.escrows)
}

/// Scan a domain's coins and return the ones this wallet owns and can open.
pub async fn scan_owned_coins(
    client: &mut Client,
    domain: &[u8],
    w: &Wallet,
) -> anyhow::Result<Vec<OwnedCoin>> {
    let coins = client
        .list_domain_coins(tonic::Request::new(ListDomainCoinsRequest { domain: domain.to_vec() }))
        .await
        .map_err(|e| anyhow::anyhow!("ListDomainCoins: {e}"))?
        .into_inner()
        .coins;

    let a_otk = &w.mp.a_otk;
    let mut owned = Vec::new();
    for c in &coins {
        if c.memo.is_empty() {
            continue;
        }
        let (kem_ct, ring_memo) = match split_output_memo(&c.memo) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let ss = match quil_crypto::sntrup761::decapsulate(&kem_ct, &w.kem_sk) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let offset = hash_to_short_polyvec(&ss, w.cols);
        let p = match wire::decode_polyvec(&c.one_time_key) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if owns_ring(a_otk, &offset, &w.big_b, &p) {
            if let Some((amt, r)) = open_ring_memo(w.np, &ss, &c.commitment, &ring_memo) {
                owned.push(OwnedCoin {
                    p_bytes: c.one_time_key.clone(),
                    sk: one_time_secret_ring(&offset, &w.b),
                    amount: amt,
                    r_coin: r,
                });
            }
        }
    }
    Ok(owned)
}

/// Fetch accumulator witnesses for `selected` coins and assemble spend inputs.
/// Returns `(root, depth, inputs)`.
pub async fn fetch_inputs(
    client: &mut Client,
    domain: &[u8],
    selected: &[OwnedCoin],
) -> anyhow::Result<(Vec<u8>, usize, Vec<SpendInput>)> {
    let otks: Vec<Vec<u8>> = selected.iter().map(|c| c.p_bytes.clone()).collect();
    let witness = client
        .get_coin_spend_witness(tonic::Request::new(GetCoinSpendWitnessRequest {
            domain: domain.to_vec(),
            one_time_keys: otks,
        }))
        .await
        .map_err(|e| anyhow::anyhow!("GetCoinSpendWitness: {e}"))?
        .into_inner();
    let depth = witness.depth as usize;
    let root = witness.root;

    let mut inputs = Vec::with_capacity(selected.len());
    for c in selected {
        let ww = witness
            .witnesses
            .iter()
            .find(|w| w.one_time_key == c.p_bytes && w.found)
            .ok_or_else(|| anyhow::anyhow!("node has no witness for a selected coin"))?;
        inputs.push(SpendInput {
            sk: c.sk.clone(),
            amount: c.amount,
            r_coin: c.r_coin.clone(),
            leaf_index: ww.leaf_index as usize,
            auth_path: ww.auth_path.clone(),
        });
    }
    Ok((root, depth, inputs))
}

/// One output coin spec: amount + the recipient's KEM pubkey and spend base.
pub struct OutSpec {
    pub amount: u128,
    pub kem_target: Vec<u8>,
    pub b_target: PolyVec,
}

/// Build the spend (with per-output KEM memos) and submit the `0x0512` message.
pub async fn submit_spend(
    client: &mut Client,
    w: &Wallet,
    domain: &[u8],
    root: &[u8],
    depth: usize,
    inputs: &[SpendInput],
    out_specs: &[OutSpec],
) -> anyhow::Result<()> {
    let a_otk = &w.mp.a_otk;

    // Derive one-time keys + KEM ciphertexts for each output.
    let mut outputs: Vec<NewOutput> = Vec::with_capacity(out_specs.len());
    let mut kem_cts: Vec<Vec<u8>> = Vec::with_capacity(out_specs.len());
    let mut secrets: Vec<Vec<u8>> = Vec::with_capacity(out_specs.len());
    for spec in out_specs {
        let (ss, kem_ct) = quil_crypto::sntrup761::encapsulate(&spec.kem_target)
            .map_err(|e| anyhow::anyhow!("encapsulate: {e}"))?;
        let offset = hash_to_short_polyvec(&ss, w.cols);
        let p_out = one_time_pubkey_ring(a_otk, &offset, &spec.b_target);
        outputs.push(NewOutput { amount: spec.amount, recipient_otk: wire::encode_polyvec(&p_out) });
        kem_cts.push(kem_ct);
        secrets.push(ss);
    }

    let seed = rand::random::<u64>();
    let tx = build_spend_transaction(w.np, root, depth, domain, inputs, &outputs, 0, seed)
        .map_err(|e| anyhow::anyhow!("build spend transaction: {e}"))?;

    let mut env = TxEnvelope::from_built(&tx);
    env.output_memos = (0..outputs.len())
        .map(|i| {
            let r_out = wire::decode_polyvec(&tx.output_rand[i])
                .map_err(|e| anyhow::anyhow!("decode output rand: {e:?}"))?;
            Ok(build_output_memo(&kem_cts[i], outputs[i].amount, &r_out, &secrets[i]))
        })
        .collect::<anyhow::Result<_>>()?;

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
    Ok(())
}

/// Map the coin identifier `token coins` prints (`hex(address)`) to the coin's
/// one-time key, so `split`/`merge` accept either form. Built from
/// `GetTokensByAccount` (a `MaterializedTransaction` carries both).
pub async fn address_to_otk(
    client: &mut Client,
    tc: &TokenCtx,
) -> anyhow::Result<HashMap<String, Vec<u8>>> {
    let account = tc.view_spend_address()?;
    let txs = client
        .get_tokens_by_account(tonic::Request::new(GetTokensByAccountRequest {
            address: account,
            domain: quil_execution::domains::QUIL_TOKEN.to_vec(),
        }))
        .await
        .map_err(|e| anyhow::anyhow!("GetTokensByAccount: {e}"))?
        .into_inner();
    let mut map = HashMap::new();
    for t in &txs.transactions {
        if !t.one_time_key.is_empty() {
            map.insert(hex::encode(&t.address), t.one_time_key.clone());
        }
    }
    Ok(map)
}

/// Resolve a user-supplied coin identifier (its `address` as printed by
/// `token coins`, or its one-time key directly) to a one-time key.
pub fn resolve_otk(arg: &str, addr_map: &HashMap<String, Vec<u8>>) -> anyhow::Result<Vec<u8>> {
    let h = arg.strip_prefix("0x").unwrap_or(arg).to_lowercase();
    if let Some(otk) = addr_map.get(&h) {
        return Ok(otk.clone());
    }
    // Fall back to treating the argument as a raw one-time key.
    hex::decode(&h).map_err(|e| anyhow::anyhow!("invalid coin identifier {arg:?}: {e}"))
}

/// Wrap `[type_prefix][inner]` as a canonical message bundle and submit it.
pub async fn submit_lattice_message(
    client: &mut Client,
    type_prefix: u32,
    inner: &[u8],
) -> anyhow::Result<()> {
    let mut msg = type_prefix.to_be_bytes().to_vec();
    msg.extend_from_slice(inner);
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
    Ok(())
}

/// Greedy coin selection covering `target` (largest-first). Returns the
/// selected coins (moved out of `owned`) and their total.
pub fn select_to_cover(mut owned: Vec<OwnedCoin>, target: u128) -> anyhow::Result<(Vec<OwnedCoin>, u128)> {
    owned.sort_by(|a, b| b.amount.cmp(&a.amount));
    let mut selected = Vec::new();
    let mut total: u128 = 0;
    for c in owned {
        if total >= target {
            break;
        }
        total += c.amount;
        selected.push(c);
    }
    if total < target {
        anyhow::bail!("insufficient balance: have {total}, need {target} (base units)");
    }
    Ok((selected, total))
}
