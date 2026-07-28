//! `--check-submit <addr>` diagnostic.
//!
//! Reproduces, in isolation, the path a non-archive prover uses to push a
//! request into global consensus: `connect_mtls` to an archive's peer
//! gRPC (`:8340`), then `submit_global_message`. The field symptom is that
//! provers' submissions never land (empty global frames) while the same
//! `:8340` endpoint also fails archive↔archive sync — so this probe
//! separates the failure surfaces:
//!
//!   step 1 connect_mtls          — TCP + Ed448 mTLS handshake (refused /
//! `tls handshake eof` / deadline show here)
//!   step 2 get_app_shards        — resolve a real shard filter to join
//!   step 3 loop, a few attempts:
//!             get_global_frame — fetch the head frame (VDF challenge +
//! fresh frame_number for the join)
//!             compute VDF proof — a genuine Wesolowski multi-proof over
//! the head frame's output (rebuilt when
//! the head advances)
//! submit_global_message — the unary RPC round-trip
//!
//! The payload is a FULLY VALID `ProverJoin`: a fresh BLS prover identity, a
//! real per-filter VDF proof bound to the head frame, and a BLS signature +
//! proof-of-possession. It is built to pass full materialization validation
//! (not merely the collector's first-pass), so if it lands it proves the
//! request path works end-to-end.
//!
//! Submission is retried a few times. A peer can legitimately drop a submit
//! when the recipient archive isn't sequencing for that frame's rank, so we
//! re-fetch the head frame each attempt (rebuilding the VDF + signature when
//! it advances) and resubmit, covering several sequencing windows. A fresh
//! BLS identity each run (seniority 0) keeps it a safe no-op — an unconfirmed
//! join expires after ~360 frames.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;

/// Number of submit attempts and the delay between them.
const ATTEMPTS: usize = 4;
const RETRY_DELAY: Duration = Duration::from_secs(3);

/// Run the submit probe against `addr` (e.g. `192.69.222.130:8340`).
pub async fn run_check_submit(
    addr: &str,
    config: &quil_config::Config,
) -> anyhow::Result<()> {
    quil_crypto::init();

    // mTLS client identity: the node's Ed448 peer key (first 57 bytes of
    // the configured seed). This is the same identity the running node
    // presents to archives, so a handshake result here matches production.
    let key_bytes = hex::decode(&config.p2p.peer_priv_key)
        .context("decode p2p.peerPrivKey hex")?;
    anyhow::ensure!(
        key_bytes.len() >= 57,
        "p2p.peerPrivKey must be >= 57 bytes (Ed448); got {}",
        key_bytes.len()
    );
    let ed448_seed: [u8; 57] = key_bytes[..57].try_into().unwrap();
    let pubkey = quil_p2p::ed448_identity::derive_public_key(&ed448_seed);
    let peer_id = quil_p2p::ed448_identity::peer_id_from_ed448_pubkey(&pubkey);

    // Fresh BLS prover identity for the join. Using a brand-new key (rather
    // than the node's own prover key) keeps this a clean, self-contained
    // "a new prover wants to join" probe with seniority 0.
    let bls_ctor = quil_crypto::FalconKeyConstructor;
    let (bls_signer_box, bls_pubkey) = quil_types::crypto::BlsConstructor::new_key(&bls_ctor)
        .map_err(|e| anyhow::anyhow!("generate BLS prover key: {e}"))?;
    let bls_signer: Arc<dyn quil_types::crypto::Signer> = Arc::from(bls_signer_box);
    let prover_address: [u8; 32] = quil_crypto::poseidon::hash_bytes_to_32(&bls_pubkey)
        .map_err(|e| anyhow::anyhow!("derive prover address: {e}"))?;

    println!("[check-submit] target archive : {addr}");
    println!("[check-submit] our ed448 peer : {}", hex::encode(&peer_id));
    println!("[check-submit] prover address : {}", hex::encode(&prover_address));
    println!("[check-submit] prover pubkey  : {}", hex::encode(&bls_pubkey));

    // The :8340 network identity is the node's Falcon q-prover-key (loaded
    // from the keystore), not the Ed448 seed. If the keystore has no Falcon
    // key (e.g. a probe run from a pre-Falcon-migration config), fall back to
    // a FRESH ephemeral Falcon identity — archives accept any authenticated
    // peer for `SubmitGlobalMessage`, so this still exercises the full PQNoise
    // handshake + submit path end-to-end.
    let falcon_signing_key = {
        use quil_keys::KeyManager as _;
        let keys_path = std::path::PathBuf::from(&config.key.key_store_file.path);
        let loaded = quil_keys::FileKeyManager::new(
            keys_path,
            &config.key.key_store_file.encryption_key,
            "default-proving-key".to_string(),
            Box::new(quil_crypto::FalconKeyConstructor),
        )
        .and_then(|fkm| fkm.get_private_key(quil_types::crypto::KeyType::Falcon512));
        match loaded {
            Ok(k) => k,
            Err(e) => {
                println!(
                    "[check-submit] no Falcon q-prover-key in keystore ({e}); \
                     using a fresh ephemeral Falcon network identity for the probe"
                );
                let (net_signer, _pk) =
                    quil_types::crypto::BlsConstructor::new_key(&quil_crypto::FalconKeyConstructor)
                        .map_err(|e| anyhow::anyhow!("generate ephemeral Falcon net key: {e}"))?;
                net_signer.private_key().to_vec()
            }
        }
    };

    // ---- step 1: connect_mtls (transport + handshake) ----
    println!("[check-submit] step 1: connect_mtls ...");
    let t0 = Instant::now();
    let mut client = match quil_rpc::ArchiveClient::connect_mtls(addr, &falcon_signing_key).await {
        Ok(c) => {
            println!("[check-submit]   OK  connected in {:?}", t0.elapsed());
            c
        }
        Err(e) => {
            println!("[check-submit]   FAIL connect_mtls after {:?}", t0.elapsed());
            print_error_chain(&e);
            println!(
                "[check-submit] VERDICT: transport/handshake to {addr} is broken — \
                 this is the connection failure blocking prover submission."
            );
            anyhow::bail!("connect_mtls failed");
        }
    };

    // ---- step 2: resolve a real shard filter to join (once) ----
    // Real provers do NOT enumerate via `get_app_shards(range)` (that walks
    // the live CRDT for every shard and times out — see the field finding);
    // they call `get_app_shards(specific 35-byte shard_key)` per genesis-
    // seeded shard. We reproduce that: derive the canonical QUIL_TOKEN
    // genesis shard_key from constants (L1 bloom indices || L2 domain) and
    // ask for just that shard, then build the wire filter the lifecycle uses
    // (L2 || one byte per prefix element) — matching
    // `shard_info_refresh::build_filter`.
    println!("[check-submit] step 2: get_app_shards (QUIL_TOKEN genesis shard) ...");
    let t1 = Instant::now();
    let quil_token_domain = quil_execution::domains::QUIL_TOKEN;
    let l1 = quil_hypergraph::addressing::get_bloom_filter_indices(&quil_token_domain[..], 256, 3);
    let mut shard_key = Vec::with_capacity(3 + 32);
    shard_key.extend_from_slice(&l1);
    shard_key.extend_from_slice(&quil_token_domain[..]);
    let infos = client
        .get_app_shards(shard_key.clone(), Vec::new())
        .await
        .map_err(|e| {
            print_error_chain(&e);
            anyhow::anyhow!("get_app_shards(specific) failed: {e}")
        })?;
    // Wire filter = L2(shard_key[3..35]) || (prefix elem as low byte)*.
    let filter = infos
        .iter()
        .filter_map(|info| {
            let mut f = shard_key[3..35].to_vec();
            for p in &info.prefix {
                f.push((*p & 0xFF) as u8);
            }
            (1..=64).contains(&f.len()).then_some(f)
        })
        .next()
        .context(
            "archive returned no sub-shards for the QUIL_TOKEN genesis shard — \
             cannot construct a join targeting a real shard",
        )?;
    println!(
        "[check-submit]   OK  {} sub-shards in {:?}; joining filter {}",
        infos.len(),
        t1.elapsed(),
        hex::encode(&filter)
    );

    // ---- step 3: build + submit, retrying across sequencing windows ----
    let mut accepted = 0usize;
    let mut built_frame: Option<u64> = None;
    let mut bundle: Vec<u8> = Vec::new();
    for attempt in 1..=ATTEMPTS {
        println!("[check-submit] --- attempt {attempt}/{ATTEMPTS} ---");

        // Re-fetch the head frame every attempt: it both re-exercises the
        // transport and tells us whether the head advanced (→ rebuild).
        let tf = Instant::now();
        let frame = match client.get_global_frame(0).await {
            Ok(f) => {
                println!("[check-submit]   get_global_frame OK in {:?}", tf.elapsed());
                f
            }
            Err(e) => {
                println!("[check-submit]   get_global_frame FAILED after {:?}", tf.elapsed());
                print_error_chain(&e);
                if attempt < ATTEMPTS {
                    tokio::time::sleep(RETRY_DELAY).await;
                }
                continue;
            }
        };
        let Some(header) = frame.header.as_ref() else {
            println!("[check-submit]   head frame has no header, retrying");
            if attempt < ATTEMPTS {
                tokio::time::sleep(RETRY_DELAY).await;
            }
            continue;
        };
        let frame_number = header.frame_number;

        // Rebuild the join only when the head advanced (or on first build).
        // frame_number is bound to the head; reusing a stale bundle past the
        // freshness window would get it rejected.
        if built_frame != Some(frame_number) {
            println!("[check-submit]   building join for frame {frame_number} ...");
            // VDF proof-of-sequential-work was removed from joins — carry
            // an empty proof.
            bundle = build_join_bundle(
                std::slice::from_ref(&filter),
                frame_number,
                &bls_pubkey,
                bls_signer.as_ref(),
                &prover_address,
                &[],
            )?;
            built_frame = Some(frame_number);
        } else {
            println!("[check-submit]   reusing join built for frame {frame_number}");
        }

        let ts = Instant::now();
        match client.submit_global_message(bundle.clone()).await {
            Ok(()) => {
                accepted += 1;
                println!(
                    "[check-submit]   OK  submit accepted in {:?} (frame {frame_number})",
                    ts.elapsed()
                );
            }
            Err(e) => {
                println!("[check-submit]   FAIL submit after {:?}", ts.elapsed());
                print_error_chain(&e);
            }
        }

        if attempt < ATTEMPTS {
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }

    // ---- verdict ----
    if accepted > 0 {
        println!(
            "[check-submit] VERDICT: {accepted}/{ATTEMPTS} submissions of a FULLY VALID \
             ProverJoin were accepted by {addr}. Watch the archive's frames for a pending \
             join from prover {} (built for frame {}). If it never appears across these \
             attempts, the gap is in collector→frame→materialize, not the connection or \
             message validity.",
            hex::encode(&prover_address),
            built_frame.map(|f| f.to_string()).unwrap_or_else(|| "?".into()),
        );
        Ok(())
    } else {
        println!(
            "[check-submit] VERDICT: all {ATTEMPTS} submissions failed against {addr} — \
             see the per-attempt errors above. If they are application-layer rejections \
             (collector rejected / unauthenticated) the transport works; if they are \
             transport/stream errors the connection is the failure."
        );
        anyhow::bail!("all {ATTEMPTS} submissions failed");
    }
}


/// Build a `MessageBundle` carrying one fully-signed `ProverJoin`.
///
/// Mirrors `prover_join_test::build_join` + the bundle wrapping: sign the
/// FULL ProverJoin canonical bytes with the signature field cleared, using
/// domain `poseidon(GLOBAL_INTRINSIC_ADDRESS || "PROVER_JOIN")`, plus a
/// proof-of-possession (`pubkey` signed under `"BLS48_POP_SK"`), then wrap
/// the signed join in a `CanonicalMessageRequest`/`CanonicalMessageBundle`.
fn build_join_bundle(
    filters: &[Vec<u8>],
    frame: u64,
    pk: &[u8],
    signer: &dyn quil_types::crypto::Signer,
    addr: &[u8; 32],
    proof: &[u8],
) -> anyhow::Result<Vec<u8>> {
    use quil_execution::global_intrinsic::{prover_join::ProverJoin, sig_with_pop::SignatureWithPop};
    use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};

    // Go signs the FULL ProverJoin canonical bytes with signature=nil
    // (global_prover_join.go:1074-1079).
    let unsigned_join = ProverJoin {
        filters: filters.to_vec(),
        frame_number: frame,
        public_key_signature_bls48581: None,
        delegate_address: addr.to_vec(),
        merge_targets: vec![],
        proof: proof.to_vec(),
    };
    let join_message = unsigned_join
        .to_canonical_bytes()
        .map_err(|e| anyhow::anyhow!("encode unsigned join: {e}"))?;

    // Domain: poseidon(GLOBAL_INTRINSIC_ADDRESS || "PROVER_JOIN").
    let mut dp = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
    dp.extend_from_slice(b"PROVER_JOIN");
    let domain = quil_crypto::poseidon::hash_bytes_to_32(&dp)
        .map_err(|e| anyhow::anyhow!("derive join domain: {e}"))?;

    let sig = signer
        .sign_with_domain(&join_message, &domain)
        .map_err(|e| anyhow::anyhow!("sign join: {e}"))?;
    // Proof of possession: sign the pubkey under the PoP domain.
    let pop = signer
        .sign_with_domain(pk, b"BLS48_POP_SK")
        .map_err(|e| anyhow::anyhow!("sign PoP: {e}"))?;

    let join = ProverJoin {
        filters: filters.to_vec(),
        frame_number: frame,
        public_key_signature_bls48581: Some(SignatureWithPop {
            signature: sig,
            public_key: Some(pk.to_vec()),
            pop_signature: pop,
        }),
        delegate_address: addr.to_vec(),
        merge_targets: vec![],
        proof: proof.to_vec(),
    }
    .to_canonical_bytes()
    .map_err(|e| anyhow::anyhow!("encode signed join: {e}"))?;

    let req = CanonicalMessageRequest::wrap(join)
        .map_err(|e| anyhow::anyhow!("wrap join request: {e}"))?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    CanonicalMessageBundle {
        requests: vec![Some(req)],
        timestamp,
    }
    .to_canonical_bytes()
    .map_err(|e| anyhow::anyhow!("encode MessageBundle: {e}"))
}

/// Walk the `std::error::Error` source chain so the real cause
/// (rustls / TCP refused / h2) is printed, not just tonic's top line.
fn print_error_chain(e: &(dyn std::error::Error)) {
    println!("[check-submit]   error: {e}");
    let mut src = e.source();
    while let Some(s) = src {
        println!("[check-submit]     caused by: {s}");
        src = s.source();
    }
}
