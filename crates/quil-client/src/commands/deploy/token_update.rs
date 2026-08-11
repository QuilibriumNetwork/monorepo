//! `qclient deploy token update -d <domain> [key=value...]`.
//!
//! Port of `client/cmd/deploy/update.go` `UpdateTokenCmd`, on the current PQ
//! auth: the owner signs the canonical `TokenUpdate` (signature field cleared)
//! with the Falcon `q-prover-key` under domain `address ‖ "TOKEN_UPDATE"`, and
//! the raw Falcon bytes go in the proto's `signature` field. (Unblocked by the
//! converter fix: `token_update_from_proto` now carries the raw sig, matching
//! the node's `engines.rs` verify.)

use std::collections::HashMap;

use num_bigint::{BigInt, Sign};

use quil_execution::token_intrinsic::conversions::token_update_from_proto;
use quil_keys::FileKeyManager;
use quil_types::crypto::Signer;
use quil_types::proto::global::{message_request::Request, MessageRequest};
use quil_types::proto::keys::Bls48581AggregateSignature;
use quil_types::proto::token::{
    ProofBasisType, TokenConfiguration, TokenMintBehavior, TokenMintStrategy, TokenUpdate,
};

use super::DeployCtx;

/// Build a signed `TokenUpdate` for `domain`. The signed message is the
/// canonical `TokenUpdate` with the signature field cleared (the node re-encodes
/// it the same way before verifying against the prior config's owner key); the
/// Falcon `q-prover-key` signs it under `domain ‖ "TOKEN_UPDATE"`.
pub(crate) fn build_token_update(
    key_manager: &FileKeyManager,
    domain: &[u8],
    cfg: TokenConfiguration,
) -> anyhow::Result<TokenUpdate> {
    // Signed message = canonical TokenUpdate with an empty signature field.
    let unsigned = TokenUpdate {
        config: Some(cfg.clone()),
        rdf_schema: Vec::new(),
        public_key_signature_bls48581: None,
    };
    let signed_message = token_update_from_proto(&unsigned)
        .map_err(|e| anyhow::anyhow!("canonicalize update: {e}"))?
        .to_canonical_bytes()
        .map_err(|e| anyhow::anyhow!("canonical bytes: {e}"))?;

    // Falcon owner signature under `domain ‖ "TOKEN_UPDATE"`.
    let mut domain_sep = domain.to_vec();
    domain_sep.extend_from_slice(b"TOKEN_UPDATE");
    let signer: Box<dyn Signer> = key_manager
        .get_signer_by_id("q-prover-key")
        .map_err(|e| anyhow::anyhow!("get owner key (q-prover-key): {e}"))?;
    let sig = signer
        .sign_with_domain(&signed_message, &domain_sep)
        .map_err(|e| anyhow::anyhow!("sign: {e}"))?;

    Ok(TokenUpdate {
        config: Some(cfg),
        rdf_schema: Vec::new(),
        public_key_signature_bls48581: Some(Bls48581AggregateSignature {
            signature: sig,
            public_key: None,
            bitmask: Vec::new(),
        }),
    })
}

const MINTABLE: u32 = 1 << 0;
const BURNABLE: u32 = 1 << 1;
const DIVISIBLE: u32 = 1 << 2;
const ACCEPTABLE: u32 = 1 << 3;
const EXPIRABLE: u32 = 1 << 4;
const TENDERABLE: u32 = 1 << 5;

pub async fn run(dc: &DeployCtx, domain_arg: &str, args: &[String]) -> anyhow::Result<()> {
    if domain_arg.is_empty() {
        anyhow::bail!("--domain <token address> is required for update");
    }
    let domain = dc.resolve_address(domain_arg, 32)?;

    // Build the (new) token configuration from key=value args.
    let mut config: HashMap<String, String> = HashMap::new();
    for arg in args {
        if let Some((k, v)) = arg.split_once('=') {
            config.insert(k.to_lowercase(), v.to_string());
        }
    }
    let keys = dc.deploy_keys()?;
    let mut cfg = TokenConfiguration {
        owner_public_key: keys.owner,
        ..Default::default()
    };
    if let Some(v) = config.get("name") {
        cfg.name = v.clone();
    }
    if let Some(v) = config.get("symbol") {
        cfg.symbol = v.clone();
    }
    if let Some(v) = config.get("behavior") {
        let mut behavior = 0u32;
        for flag in v.split(',') {
            behavior |= match flag.trim().to_lowercase().as_str() {
                "mintable" => MINTABLE,
                "burnable" => BURNABLE,
                "divisible" => DIVISIBLE,
                "acceptable" => ACCEPTABLE,
                "expirable" => EXPIRABLE,
                "tenderable" => TENDERABLE,
                other => anyhow::bail!("unknown behavior flag: {other}"),
            };
        }
        cfg.behavior = behavior;
    }
    if let Some(v) = config.get("mintstrategy") {
        let mut strat = TokenMintStrategy::default();
        match v.to_lowercase().as_str() {
            "proof" => {
                strat.mint_behavior = TokenMintBehavior::MintWithProof as i32;
                strat.proof_basis = ProofBasisType::ProofOfMeaningfulWork as i32;
            }
            "authority" => strat.mint_behavior = TokenMintBehavior::MintWithAuthority as i32,
            "signature" => strat.mint_behavior = TokenMintBehavior::MintWithSignature as i32,
            "payment" => strat.mint_behavior = TokenMintBehavior::MintWithPayment as i32,
            other => anyhow::bail!("unknown mint strategy: {other}"),
        }
        cfg.mint_strategy = Some(strat);
    }
    if let Some(v) = config.get("units") {
        cfg.units = parse_bigint_be(v)?;
    }
    if let Some(v) = config.get("supply") {
        cfg.supply = parse_bigint_be(v)?;
    }

    let signed = build_token_update(&dc.key_manager, &domain, cfg)?;

    let mut client = dc.connect().await?;
    let request = MessageRequest {
        request: Some(Request::TokenUpdate(signed)),
        timestamp: 0,
    };
    // Updates are submitted on the token's own domain.
    crate::send::send_message_request(&mut client, &dc.key_manager, domain, request).await?;
    println!("Token update submitted successfully");
    Ok(())
}

fn parse_bigint_be(s: &str) -> anyhow::Result<Vec<u8>> {
    let n: BigInt = s.parse().map_err(|_| anyhow::anyhow!("invalid integer: {s}"))?;
    if n == BigInt::from(0) {
        return Ok(Vec::new());
    }
    if n.sign() == Sign::Minus {
        anyhow::bail!("negative value: {s}");
    }
    Ok(n.to_bytes_be().1)
}
