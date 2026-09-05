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

/// The KEM public-key length — the CANONICAL crypto-crate constant, so the
/// address offsets can never silently drift from the KEM if it changes.
const SNTRUP761_PK_LEN: usize = quil_crypto::sntrup761::SNTRUP761_PUBLIC_KEY_LEN;
/// KEM identity tag folded into the address parameter fingerprint (below), so a
/// KEM change — which the `R_q` fingerprint alone would miss — also invalidates
/// old addresses (an unspendable-coin guard on the stealth/memo side).
const KEM_ID: &[u8] = b"sntrup761";

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

/// Confidential-address wire version (byte 0 of the address).
pub const ADDR_VERSION: u8 = 1;
/// Escrow/pending address version (DISTINCT from `ADDR_VERSION`), so a
/// confidential address pasted into a pending-transfer (or vice-versa) fails
/// closed instead of silently misparsing into garbage keys → locked funds.
pub const PENDING_VERSION: u8 = 2;
/// Length of the lattice-parameters fingerprint embedded in the address.
pub const ADDR_FP_LEN: usize = 8;

/// A fingerprint of the lattice parameters that make a spend public key `B`
/// meaningful: the modulus `q`, the ring degree `d`, and the full OTK matrix
/// `A_otk` (itself a function of `q`, `κ`, `λ`, and its seed, since `B = A_otk·b`).
/// An address minted under different parameters carries a DIFFERENT fingerprint,
/// so a cross-parameter send FAILS CLOSED (the recipient could never spend a coin
/// created under the sender's mismatched `A_otk`/`q`).
pub fn params_fingerprint() -> [u8; ADDR_FP_LEN] {
    use sha2::{Digest, Sha256};
    let mp = MembershipParams::production(1);
    let mut h = Sha256::new();
    h.update(b"quil-lattice-ct/address-params-fingerprint/v2");
    h.update(quil_lattice_ct::params::MODULUS_Q.to_le_bytes());
    h.update((quil_lattice_ct::rq::Poly::D as u64).to_le_bytes());
    // Bind the KEM identity too: the address carries a KEM pubkey and spendability
    // needs the KEM to match (sender encapsulates / recipient decapsulates). A KEM
    // change that left q/d/A_otk untouched would otherwise pass unnoticed.
    h.update((KEM_ID.len() as u64).to_le_bytes());
    h.update(KEM_ID);
    h.update((SNTRUP761_PK_LEN as u64).to_le_bytes());
    for row in &mp.a_otk.m {
        for p in row {
            for &c in &p.c {
                h.update(c.to_le_bytes());
            }
        }
    }
    let d = h.finalize();
    let mut fp = [0u8; ADDR_FP_LEN];
    fp.copy_from_slice(&d[..ADDR_FP_LEN]);
    fp
}

/// Serialize this wallet's confidential receiving address:
/// `VERSION(1) ‖ FINGERPRINT(8) ‖ kem_pk ‖ wire(B)`.
pub fn encode_address(kem_pk: &[u8], big_b: &PolyVec) -> Vec<u8> {
    debug_assert_eq!(
        kem_pk.len(),
        SNTRUP761_PK_LEN,
        "kem_pk must be exactly the KEM public-key length, else parse offsets corrupt both fields"
    );
    let mut out = Vec::with_capacity(1 + ADDR_FP_LEN + kem_pk.len() + 4);
    out.push(ADDR_VERSION);
    out.extend_from_slice(&params_fingerprint());
    out.extend_from_slice(kem_pk);
    out.extend_from_slice(&wire::encode_polyvec(big_b));
    out
}

/// Parse a `VERSION ‖ FINGERPRINT ‖ kem_pk ‖ wire(B)` recipient address, and
/// REJECT (fail closed) if it was minted under different lattice parameters —
/// sending to such an address would create a coin the recipient cannot spend.
pub fn parse_address(hex_str: &str) -> anyhow::Result<LatticeAddress> {
    let raw = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
        .map_err(|e| anyhow::anyhow!("invalid recipient address hex: {e}"))?;
    let header = 1 + ADDR_FP_LEN;
    if raw.len() <= header + SNTRUP761_PK_LEN {
        anyhow::bail!("recipient address too short");
    }
    if raw[0] != ADDR_VERSION {
        anyhow::bail!(
            "unsupported confidential-address version {} (expected {}) — the address \
             format changed; ask the recipient for a current address.",
            raw[0],
            ADDR_VERSION
        );
    }
    let fp = &raw[1..header];
    let expected = params_fingerprint();
    if fp != expected {
        anyhow::bail!(
            "recipient confidential address was generated under DIFFERENT lattice \
             parameters (modulus q / OTK matrix). REFUSING to send: a coin created for \
             this address would be UNSPENDABLE by the recipient. Ask the recipient for \
             an address generated under the current parameters."
        );
    }
    let body = &raw[header..];
    let kem_pk = body[..SNTRUP761_PK_LEN].to_vec();
    let big_b = wire::decode_polyvec(&body[SNTRUP761_PK_LEN..])
        .map_err(|e| anyhow::anyhow!("invalid recipient B: {e:?}"))?;
    Ok(LatticeAddress { kem_pk, big_b })
}

/// The wallet's long-term lattice spend base `b` (eta=1, so stealth
/// `sk = offset + b` stays within the membership norm bound ETA=2).
///
/// DERIVED deterministically from the wallet's encrypted `q-onion-key` keystore
/// secret — it is NEVER written to disk. This replaces the first-cut plaintext
/// `q-lattice-spend.key` file (a spend secret in the clear). Derivation is
/// domain-separated so it can never collide with the stealth-offset derivation,
/// and full-entropy (`hash_to_short_polyvec` expands the seed with SHA-256), so
/// `b` retains the seed's entropy (a truncated PRG seed would have weakened it).
///
/// Backward-compat: if a legacy plaintext file still exists (a wallet from the
/// first-cut), it is read (so coins made under that `b` remain spendable) with a
/// loud deprecation warning; delete it once migrated.
pub fn derive_spend_base(
    config_dir: &std::path::Path,
    onion_secret: &[u8],
    cols: usize,
) -> anyhow::Result<PolyVec> {
    let legacy = config_dir.join("q-lattice-spend.key");
    if legacy.exists() {
        // A legacy plaintext key is used ONLY if it decodes AND validates. Two
        // failure modes are DISTINGUISHED, because they are NOT the same risk:
        //   * decode succeeds but validation fails → a well-formed key that is
        //     incompatible with the current parameters (the clean "params changed"
        //     signal). Regenerate.
        //   * decode FAILS (unreadable / non-hex / truncated / wrong wire) → could
        //     be a genuine parameter mismatch OR local CORRUPTION of a real key.
        //     We still regenerate (the derived keystore key is the canonical
        //     identity), but we flag corruption explicitly so a user who DID hold a
        //     standalone legacy key is warned that a NEW spend identity is adopted.
        // NOTE: adopting a new identity makes any coins held under the OLD key
        // inaccessible. This is safe only while no confidential coins exist; a
        // confirmation gate should precede launch (see LABRADOR_ASSESSMENT §8.5).
        let decoded = std::fs::read_to_string(&legacy)
            .ok()
            .and_then(|s| hex::decode(s.trim()).ok())
            .and_then(|raw| wire::decode_polyvec(&raw).ok());
        match decoded {
            Some(b) if validate_spend_base(&b, cols).is_ok() => {
                eprintln!(
                    "[WARN] using DEPRECATED plaintext lattice spend key {} — the spend \
                     base is now derived from the (encrypted) keystore; delete this file \
                     once your coins are migrated so no spend secret sits in the clear.",
                    legacy.display()
                );
                return Ok(b);
            }
            Some(_) => {
                eprintln!(
                    "[WARN] legacy lattice spend key {} decoded but is INCOMPATIBLE with \
                     the current lattice parameters — REGENERATING the canonical spend \
                     base from your keystore secret. Any coins held under the OLD key \
                     will be INACCESSIBLE under the new key; recover them first if you \
                     have any. Delete the stale file once done.",
                    legacy.display()
                );
            }
            None => {
                eprintln!(
                    "[WARN] legacy lattice spend key {} could NOT be decoded (unreadable, \
                     truncated, or from different parameters — possibly CORRUPTED). \
                     REGENERATING the canonical spend base from your keystore secret. If \
                     this file was a real, coin-bearing key, those coins will be \
                     INACCESSIBLE under the regenerated identity — restore a good copy of \
                     the key before proceeding if so.",
                    legacy.display()
                );
            }
        }
        // Regenerate ONCE: move the stale/incompatible file aside so subsequent
        // loads go straight to the (deterministic) derived key without re-warning
        // or re-regenerating. Bytes are PRESERVED in a `.bak` (never deleted), so a
        // user who needs to recover an old coin-bearing key still has them.
        let bak = legacy.with_file_name("q-lattice-spend.key.incompatible.bak");
        match std::fs::rename(&legacy, &bak) {
            Ok(()) => eprintln!(
                "[INFO] moved the stale spend key to {} — the wallet will use the derived \
                 key from now on (this one-time migration will not repeat).",
                bak.display()
            ),
            Err(e) => eprintln!(
                "[WARN] could not move the stale spend key {} aside ({e}); it will be \
                 re-checked on the next run. Move or delete it manually to silence this.",
                legacy.display()
            ),
        }
        // fall through to derivation
    }
    // Domain-separated seed = SHA3-256("…/wallet-spend-base/v1" ‖ onion_secret),
    // then a full-entropy short-vector expansion (eta=1). This derivation is
    // MODULUS-INDEPENDENT (produces a ternary vector), so it re-derives IDENTICALLY
    // under any q — a q change never silently corrupts the derived spend key.
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"quil-lattice-ct/wallet-spend-base/v1");
    h.update(onion_secret);
    let seed = h.finalize();
    let b = quil_lattice_ct::stealth::hash_to_short_polyvec(&seed, cols);
    // Defensive: the derived key MUST validate; a failure here is a params bug.
    validate_spend_base(&b, cols)?;
    Ok(b)
}

/// Reject a spend base that is not compatible with the current lattice
/// parameters. A valid spend base is (a) the right module rank (`cols`) and
/// (b) ternary (`‖b‖∞ ≤ 1`, the derivation's η=1 invariant, so that the stealth
/// `sk = offset + b` stays within the membership bound `‖sk‖∞ ≤ SECRET_NORM_ETA`
/// (=2) given `offset` is also η=1). A key generated under a different modulus
/// `q` decodes to a large-coefficient / wrong-length vector and is caught here —
/// so the wallet NEVER silently signs with an incompatible key (which would
/// produce coins nobody can spend, or spends that don't verify).
fn validate_spend_base(b: &PolyVec, cols: usize) -> anyhow::Result<()> {
    if b.len() != cols {
        anyhow::bail!(
            "lattice spend base has module rank {} but the current parameters expect {} — \
             INCOMPATIBLE (generated under different lattice parameters). Refusing to use it. \
             If you hold no confidential coins under the old key, remove the stale key so it \
             re-derives from your keystore under the current parameters.",
            b.len(),
            cols
        );
    }
    // The spend base is η=1 by construction; enforcing ≤1 (not SECRET_NORM_ETA=2)
    // is the tight bound that actually guarantees ‖offset+b‖∞ ≤ 2.
    let bound = 1u64;
    let norm = b.inf_norm();
    if norm > bound {
        anyhow::bail!(
            "lattice spend base is NOT short (‖b‖∞ = {norm} > {bound}) — this key is \
             INCOMPATIBLE with the current modulus q (its coefficients decoded to \
             large values, the signature of a key generated under a different q). \
             Refusing to sign with a corrupt spend key. If you hold no confidential \
             coins under the old key, regenerate by removing the stale key so the \
             spend base re-derives from your (modulus-independent) keystore secret."
        );
    }
    Ok(())
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
        let km = &tc.key_manager;
        let kem_sk = km
            .get_secret_key_bytes_by_id("q-onion-key")
            .map_err(|e| anyhow::anyhow!("q-onion-key secret: {e}"))?;
        let kem_pk = km
            .get_public_key_bytes_by_id("q-onion-key")
            .map_err(|e| anyhow::anyhow!("q-onion-key public: {e}"))?;
        // Derive the spend base from the (encrypted) keystore onion secret — no
        // plaintext spend key on disk.
        let b = derive_spend_base(&tc.config_dir, &kem_sk, cols)?;
        let big_b = mp.a_otk.matvec(&b);
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

    /// This wallet's escrow/pending receiving address:
    /// `hex(PENDING_VERSION ‖ kem_pk ‖ falcon_pk)`.
    pub fn pending_address(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(1 + self.kem_pk.len() + self.falcon_pk.len());
        a.push(PENDING_VERSION);
        a.extend_from_slice(&self.kem_pk);
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
    if raw.len() <= 1 + SNTRUP761_PK_LEN {
        anyhow::bail!("pending address too short (expected VERSION ‖ kem_pk ‖ falcon_pk)");
    }
    if raw[0] != PENDING_VERSION {
        // A confidential address (ADDR_VERSION) or any other type must NOT be
        // silently misparsed into a garbage claim key → locked escrow.
        anyhow::bail!(
            "not a pending/escrow address (version {} ≠ {}) — did you paste a confidential \
             address? Use `token transfer` for that.",
            raw[0],
            PENDING_VERSION
        );
    }
    let body = &raw[1..];
    let kem_pk = body[..SNTRUP761_PK_LEN].to_vec();
    let falcon_pk = body[SNTRUP761_PK_LEN..].to_vec();
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
    // Packed-only by default: `build_spend_transaction` emits the coefficient-packed
    // per-limb ranges in `output_range_proofs` (the legacy range_rq format is retired).
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
    // `env.output_range_proofs` already carries the packed per-limb ranges
    // (copied from the built tx by `from_built`).

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

#[cfg(test)]
mod spend_key_guard_tests {
    use super::*;
    use quil_lattice_ct::rq::Poly;

    /// The compatibility guard: a valid (short, right-rank) spend base passes;
    /// a wrong-rank one and a non-short one (the signature of a key generated
    /// under a different modulus q) are REJECTED, never silently accepted.
    #[test]
    fn validate_spend_base_rejects_incompatible() {
        let cols = 4usize;
        // Honest derived spend base: ternary, short → accepted.
        let good = hash_to_short_polyvec(b"seed-material-for-test", cols);
        assert!(validate_spend_base(&good, cols).is_ok(), "honest short spend base accepted");

        // Wrong module rank → rejected.
        assert!(validate_spend_base(&good, cols + 1).is_err(), "wrong-rank key rejected");

        // Non-short key (a large coefficient ~ the shape of a key decoded under a
        // DIFFERENT modulus q) → rejected loudly.
        let mut polys = good.0.clone();
        let mut c = vec![0i64; Poly::D];
        c[0] = (Poly::Q / 2) as i64; // huge centered coefficient
        polys[0] = Poly::from_signed(&c);
        let corrupt = PolyVec(polys);
        assert!(validate_spend_base(&corrupt, cols).is_err(), "non-short (q-incompatible) key rejected");
    }

    /// An INCOMPATIBLE legacy plaintext spend key is NOT used and NOT a hard
    /// error — `derive_spend_base` REGENERATES a valid short key from the
    /// (modulus-independent) keystore secret. Safe because no coins exist.
    #[test]
    fn derive_spend_base_regenerates_on_incompatible_legacy() {
        let dir = std::env::temp_dir().join(format!("quil-spendkey-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let cols = 4usize;
        // Write an incompatible legacy key: a wire-encoded vector with a huge
        // (non-short) coefficient — the signature of a key from a different q.
        let mut polys = hash_to_short_polyvec(b"x", cols).0;
        let mut c = vec![0i64; Poly::D];
        c[0] = (Poly::Q / 2) as i64;
        polys[0] = Poly::from_signed(&c);
        let bad = PolyVec(polys);
        let encoded = hex::encode(wire::encode_polyvec(&bad));
        std::fs::write(dir.join("q-lattice-spend.key"), encoded).unwrap();

        // derive_spend_base must NOT return the corrupt key; it regenerates.
        let b = derive_spend_base(&dir, b"onion-secret-material", cols).expect("regenerates");
        assert!(validate_spend_base(&b, cols).is_ok(), "regenerated key is valid + short");
        assert_ne!(b.0, bad.0, "did not use the incompatible legacy key");
        // ONE-TIME: the stale file is moved aside (preserved as .bak, not deleted),
        // so the migration does not repeat on the next load.
        assert!(!dir.join("q-lattice-spend.key").exists(), "stale key moved aside");
        assert!(dir.join("q-lattice-spend.key.incompatible.bak").exists(), "stale bytes preserved in .bak");
        // Deterministic + does not regenerate again: same secret → same key,
        // now via the plain derivation path (no legacy file present).
        let b2 = derive_spend_base(&dir, b"onion-secret-material", cols).unwrap();
        assert_eq!(b.0, b2.0, "derivation is deterministic and stable across loads");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The address parameter fingerprint round-trips, and a mismatched
    /// fingerprint / version is REJECTED (cross-parameter sends fail closed).
    #[test]
    fn address_fingerprint_round_trips_and_rejects_mismatch() {
        let kem_pk = vec![7u8; SNTRUP761_PK_LEN];
        let big_b = hash_to_short_polyvec(b"B-material", 4);
        let addr = encode_address(&kem_pk, &big_b);
        let hex_addr = hex::encode(&addr);
        // Round-trip under the current params.
        let parsed = parse_address(&hex_addr).expect("current-params address parses");
        assert_eq!(parsed.kem_pk, kem_pk);
        assert_eq!(parsed.big_b.0, big_b.0);
        assert_eq!(&addr[1..1 + ADDR_FP_LEN], &params_fingerprint()[..], "fingerprint embedded");

        // Flip a fingerprint byte → different (foreign) parameters → REJECTED.
        let mut foreign = addr.clone();
        foreign[1] ^= 0xFF;
        assert!(parse_address(&hex::encode(&foreign)).is_err(), "mismatched-param address rejected");

        // Unsupported version → REJECTED.
        let mut bad_ver = addr.clone();
        bad_ver[0] = ADDR_VERSION.wrapping_add(1);
        assert!(parse_address(&hex::encode(&bad_ver)).is_err(), "wrong version rejected");
    }

    /// Confidential and escrow/pending addresses have DISTINCT version bytes, so
    /// pasting one where the other is expected fails closed (no garbage misparse
    /// → no locked funds).
    #[test]
    fn address_types_do_not_cross_parse() {
        let kem_pk = vec![7u8; SNTRUP761_PK_LEN];
        let big_b = hash_to_short_polyvec(b"B", 4);
        let conf = encode_address(&kem_pk, &big_b); // ADDR_VERSION
        assert!(
            parse_pending_address(&hex::encode(&conf)).is_err(),
            "a confidential address must NOT parse as a pending/escrow address"
        );
        // A pending address: PENDING_VERSION ‖ kem_pk ‖ falcon_pk.
        let mut pend = vec![PENDING_VERSION];
        pend.extend_from_slice(&kem_pk);
        pend.extend_from_slice(&[9u8; 64]); // dummy falcon_pk
        assert!(
            parse_address(&hex::encode(&pend)).is_err(),
            "a pending address must NOT parse as a confidential address"
        );
        let parsed = parse_pending_address(&hex::encode(&pend)).expect("pending parses under its own version");
        assert_eq!(parsed.kem_pk, kem_pk);
        assert_eq!(parsed.falcon_pk, vec![9u8; 64]);
    }
}
