//! `qclient deploy token [key=value...]`.
//!
//! Port of `client/cmd/deploy/deploy.go` `DeployTokenCmd`. No inner
//! signature; the node materializes the owner from the config's
//! `owner_public_key` (Falcon-512 here, not the Go BLS key).

use std::collections::HashMap;

use num_bigint::{BigInt, Sign};

use quil_types::proto::global::{message_request::Request, MessageRequest};
use quil_types::proto::token::{
    ProofBasisType, TokenConfiguration, TokenDeploy, TokenMintBehavior, TokenMintStrategy,
};

use super::DeployCtx;

// Behavior bit flags (token_intrinsic/constants.rs).
const MINTABLE: u32 = 1 << 0;
const BURNABLE: u32 = 1 << 1;
const DIVISIBLE: u32 = 1 << 2;
const ACCEPTABLE: u32 = 1 << 3;
const EXPIRABLE: u32 = 1 << 4;
const TENDERABLE: u32 = 1 << 5;

pub async fn run(dc: &DeployCtx, args: &[String]) -> anyhow::Result<()> {
    let mut config: HashMap<String, String> = HashMap::new();
    for arg in args {
        if let Some((k, v)) = arg.split_once('=') {
            config.insert(k.to_lowercase(), v.to_string());
        }
    }

    let mut cfg = TokenConfiguration::default();
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
            other => anyhow::bail!(
                "unknown mint strategy: {other} (valid: proof, authority, signature, payment)"
            ),
        }
        cfg.mint_strategy = Some(strat);
    }
    if let Some(v) = config.get("units") {
        cfg.units = parse_bigint_be(v).map_err(|_| anyhow::anyhow!("invalid units value: {v}"))?;
    }
    if let Some(v) = config.get("supply") {
        cfg.supply = parse_bigint_be(v).map_err(|_| anyhow::anyhow!("invalid supply value: {v}"))?;
    }

    let keys = dc.deploy_keys()?;
    cfg.owner_public_key = keys.owner;

    let mut client = dc.connect().await?;
    let request = MessageRequest {
        request: Some(Request::TokenDeploy(TokenDeploy {
            config: Some(cfg.clone()),
            rdf_schema: Vec::new(),
        })),
        timestamp: 0,
    };
    dc.send_deploy(&mut client, request).await?;

    println!("Token deployed successfully");
    if !cfg.name.is_empty() {
        println!("  Name: {}", cfg.name);
    }
    if !cfg.symbol.is_empty() {
        println!("  Symbol: {}", cfg.symbol);
    }
    Ok(())
}

/// Parse a base-10 big integer to big-endian bytes (`big.Int.Bytes()`).
fn parse_bigint_be(s: &str) -> anyhow::Result<Vec<u8>> {
    let n: BigInt = s.parse().map_err(|_| anyhow::anyhow!("not an integer"))?;
    let (_, bytes) = n.to_bytes_be();
    // big.Int.Bytes() drops the sign and returns [] for zero.
    if n == BigInt::from(0) {
        Ok(Vec::new())
    } else if n.sign() == Sign::Minus {
        anyhow::bail!("negative value")
    } else {
        Ok(bytes)
    }
}
