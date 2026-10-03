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
            // Custom tokens never mint by proof of meaningful work: the proof
            // basis is a Merkle root of mint entitlements in this config
            // (`token entitlements` builds it and prints each proof).
            "proof" => {
                strat.mint_behavior = TokenMintBehavior::MintWithProof as i32;
                strat.proof_basis = ProofBasisType::MerkleEntitlementWithSignature as i32;
            }
            "authority" => strat.mint_behavior = TokenMintBehavior::MintWithAuthority as i32,
            "signature" => strat.mint_behavior = TokenMintBehavior::MintWithSignature as i32,
            "payment" => strat.mint_behavior = TokenMintBehavior::MintWithPayment as i32,
            other => anyhow::bail!(
                "unknown mint strategy: {other} (valid: proof, authority, signature, payment)"
            ),
        }
        // The mint authority: a keystore key id, resolved to its public key.
        // Application authority keys are post-quantum only (Falcon-512).
        if let Some(id) = config.get("authoritykey") {
            let signer = dc.key_manager.get_signer_by_id(id)
                .map_err(|e| anyhow::anyhow!("mint authority key {id}: {e}"))?;
            anyhow::ensure!(
                quil_execution::token_intrinsic::signature::is_post_quantum_authority(signer.key_type() as u32),
                "mint authority keys must be post-quantum (Falcon-512): {id} is not"
            );
            strat.authority = Some(quil_types::proto::token::Authority {
                key_type: signer.key_type() as u32,
                public_key: signer.public_key().to_vec(),
                can_burn: config.get("canburn").is_some_and(|v| v == "true"),
            });
        }
        // A paid mint: the price per unit, paid to this payment address (the
        // payee's `token payment-address`).
        if let Some(v) = config.get("paymentaddress") {
            let address = hex::decode(v.strip_prefix("0x").unwrap_or(v))
                .map_err(|_| anyhow::anyhow!("payment address is not hex: {v}"))?;
            anyhow::ensure!(address.len() == 32, "a payment address is 32 bytes");
            strat.payment_address = address;
        }
        if let Some(v) = config.get("price") {
            let baseline: u128 = v.parse().map_err(|_| anyhow::anyhow!("price is not a number: {v}"))?;
            strat.fee_basis = Some(quil_types::proto::token::FeeBasis {
                r#type: quil_types::proto::token::FeeBasisType::PerUnit as i32,
                baseline: BigInt::from(baseline).to_bytes_be().1,
            });
        }
        // The entitlement root of a proof-basis token (`token entitlements`).
        if let Some(v) = config.get("entitlementroot") {
            let root = hex::decode(v.strip_prefix("0x").unwrap_or(v))
                .map_err(|_| anyhow::anyhow!("entitlement root is not hex: {v}"))?;
            anyhow::ensure!(root.len() == 32, "an entitlement root is 32 bytes");
            strat.verkle_root = root;
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

    // The domain this configuration derives, so the deployer can address the
    // token it just created (the node derives the same value).
    let domain = quil_execution::token_intrinsic::materialize::token_deploy_domain(
        &quil_execution::token_intrinsic::conversions::token_config_from_proto(&cfg)
            .map_err(|e| anyhow::anyhow!("token configuration: {e}"))?,
    ).map_err(|e| anyhow::anyhow!("deploy domain: {e}"))?;

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
    println!("Domain: {}", hex::encode(domain));
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
