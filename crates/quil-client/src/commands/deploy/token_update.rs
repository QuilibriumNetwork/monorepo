//! `qclient deploy token update -d <domain> [key=value...]`.
//!
//! Port of `client/cmd/deploy/update.go` `UpdateTokenCmd`, on the current PQ
//! auth: the owner signs the canonical `TokenUpdate` (signature field cleared)
//! with the Falcon `q-prover-key` under domain `address ‖ "TOKEN_UPDATE"`,
//! followed from the config replay frame by the digest of the configuration
//! the update replaces, and the raw Falcon bytes go in the proto's `signature`
//! field (`token_update_from_proto` carries the raw sig, matching the node's
//! `engines.rs` verify).
//!
//! The node replaces the token's whole configuration with the update's, so the
//! update starts from the configuration on chain and changes only the fields
//! given; it is never built from defaults.

use std::collections::HashMap;

use num_bigint::{BigInt, BigUint, Sign};
use tonic::transport::Channel;

use quil_execution::config_replay::{update_signing_domain, TOKEN_UPDATE_TAG};
use quil_execution::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS;
use quil_execution::token_intrinsic::conversions::{
    token_config_to_proto, token_update_from_proto,
};
use quil_execution::token_intrinsic::materialize::TOKEN_CONFIG_OUTER_KEY;
use quil_execution::token_intrinsic::metadata_schema::decode_token_config_from_tree;
use quil_keys::FileKeyManager;
use quil_types::crypto::Signer;
use quil_types::proto::global::{message_request::Request, MessageRequest};
use quil_types::proto::keys::Bls48581AggregateSignature;
use quil_types::proto::node::node_service_client::NodeServiceClient;
use quil_types::proto::node::GetVertexDataRequest;
use quil_types::proto::token::{
    FeeBasisType, ProofBasisType, TokenConfiguration, TokenMintBehavior, TokenMintStrategy,
    TokenUpdate,
};

use super::{check_key_args, DeployCtx};

/// Build a signed `TokenUpdate` for `domain`. The signed message is the
/// canonical `TokenUpdate` with the signature field cleared (the node re-encodes
/// it the same way before verifying against the prior config's owner key); the
/// Falcon `q-prover-key` signs it under `domain ‖ "TOKEN_UPDATE"`, followed by
/// `binding`, the digest of the metadata vertex the update replaces, when given
/// ([`DeployCtx::update_binding`]).
pub(crate) fn build_token_update(
    key_manager: &FileKeyManager,
    domain: &[u8],
    cfg: TokenConfiguration,
    binding: Option<&[u8]>,
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

    // Falcon owner signature under `domain ‖ "TOKEN_UPDATE" [‖ binding]`.
    let domain_sep = update_signing_domain(domain, TOKEN_UPDATE_TAG, binding);
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

/// The keys an update sets.
const UPDATE_KEYS: [&str; 7] = [
    "name",
    "symbol",
    "behavior",
    "mintstrategy",
    "units",
    "supply",
    "additionalreference",
];

/// The strategy `mintstrategy=proof` sets, as `deploy token` does: a custom
/// token mints by proof against the Merkle root of entitlements in its
/// configuration. The node refuses its mints by proof of meaningful work.
pub(super) fn proof_mint_strategy() -> TokenMintStrategy {
    TokenMintStrategy {
        mint_behavior: TokenMintBehavior::MintWithProof as i32,
        proof_basis: ProofBasisType::MerkleEntitlementWithSignature as i32,
        ..Default::default()
    }
}

const MINTABLE: u32 = 1 << 0;
const BURNABLE: u32 = 1 << 1;
const DIVISIBLE: u32 = 1 << 2;
const ACCEPTABLE: u32 = 1 << 3;
const EXPIRABLE: u32 = 1 << 4;
const TENDERABLE: u32 = 1 << 5;

const BEHAVIOR_FLAGS: [(u32, &str); 6] = [
    (MINTABLE, "mintable"),
    (BURNABLE, "burnable"),
    (DIVISIBLE, "divisible"),
    (ACCEPTABLE, "acceptable"),
    (EXPIRABLE, "expirable"),
    (TENDERABLE, "tenderable"),
];

pub async fn run(dc: &DeployCtx, domain_arg: &str, args: &[String]) -> anyhow::Result<()> {
    if domain_arg.is_empty() {
        anyhow::bail!("--domain <token address> is required for update");
    }
    check_key_args(args, &UPDATE_KEYS)?;
    let domain = dc.resolve_address(domain_arg, 32)?;

    let mut client = dc.connect().await?;
    let (current, vertex) = read_config(&mut client, &domain).await?;
    let cfg = update_config(dc, &current, args)?;
    let binding = dc
        .update_binding(&mut client, &domain, Some(&vertex))
        .await?;

    println!("Domain: {}", hex::encode(&domain));
    let changes = changed_fields(&current, &cfg);
    if changes.is_empty() {
        println!("  No configuration changes");
    }
    for change in &changes {
        println!("  {change}");
    }

    let signed = build_token_update(&dc.key_manager, &domain, cfg, binding.as_deref())?;
    let request = MessageRequest {
        request: Some(Request::TokenUpdate(signed)),
        timestamp: 0,
    };
    // Updates are submitted on the token's own domain.
    dc.send_paid(&mut client, &domain, request).await?;
    println!("Token update submitted successfully");
    Ok(())
}

/// The token's configuration as the chain holds it, with its metadata vertex.
/// Any failure refuses the update: one built without it would erase every
/// field it does not set.
async fn read_config(
    client: &mut NodeServiceClient<Channel>,
    domain: &[u8],
) -> anyhow::Result<(TokenConfiguration, Vec<u8>)> {
    let refused = "an update replaces the whole configuration, so nothing was sent";
    let mut address = domain.to_vec();
    address.extend_from_slice(&HYPERGRAPH_METADATA_ADDRESS);
    let response = client
        .get_vertex_data(tonic::Request::new(GetVertexDataRequest {
            address,
            full_data: true,
        }))
        .await
        .map_err(|e| anyhow::anyhow!("could not read the token's configuration: {e}; {refused}"))?
        .into_inner();
    if response.present == Some(false) || response.raw_data.is_empty() {
        anyhow::bail!(
            "no configuration found for token {}; {refused}",
            hex::encode(domain)
        );
    }
    let cfg = config_from_metadata_vertex(&response.raw_data).map_err(|e| {
        anyhow::anyhow!("could not decode the token's configuration: {e}; {refused}")
    })?;
    Ok((cfg, response.raw_data))
}

/// Decode a token's configuration from its metadata vertex (the serialized
/// tree at `domain ‖ HYPERGRAPH_METADATA_ADDRESS`), as the node reads it
/// before an update.
pub(crate) fn config_from_metadata_vertex(blob: &[u8]) -> anyhow::Result<TokenConfiguration> {
    let outer = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(blob)
            .map_err(|e| anyhow::anyhow!("metadata vertex: {e}"))?,
    };
    let inner_blob = outer
        .get(&TOKEN_CONFIG_OUTER_KEY)
        .ok_or_else(|| anyhow::anyhow!("the address holds no token configuration"))?;
    let inner = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(inner_blob)
            .map_err(|e| anyhow::anyhow!("configuration tree: {e}"))?,
    };
    let canonical = decode_token_config_from_tree(&inner).map_err(|e| anyhow::anyhow!("{e}"))?;
    // The proto carries the name and symbol as text; other bytes would change.
    for (field, bytes) in [("name", &canonical.name), ("symbol", &canonical.symbol)] {
        anyhow::ensure!(
            std::str::from_utf8(bytes).is_ok(),
            "the token's {field} is not UTF-8 text, so an update cannot keep it"
        );
    }
    let mut cfg = token_config_to_proto(&canonical).map_err(|e| anyhow::anyhow!("{e}"))?;
    // The node stores the references as one field; an empty one is none.
    cfg.additional_reference.retain(|r| !r.is_empty());
    Ok(cfg)
}

/// The configuration an update submits, as `updated_config` builds it, with
/// the `additionalreference` arg (hex or an alias) replacing the token's
/// additional reference; without the arg the token keeps its reference.
pub(super) fn update_config(
    dc: &DeployCtx,
    current: &TokenConfiguration,
    args: &[String],
) -> anyhow::Result<TokenConfiguration> {
    let mut cfg = updated_config(current, args)?;
    if let Some(reference) = super::token::additional_reference(dc, args)? {
        cfg.additional_reference = vec![reference];
    }
    Ok(cfg)
}

/// The configuration an update submits: the token's current configuration
/// with the fields named in the `key=value` args replaced.
pub(crate) fn updated_config(
    current: &TokenConfiguration,
    args: &[String],
) -> anyhow::Result<TokenConfiguration> {
    let mut config: HashMap<String, String> = HashMap::new();
    for arg in args {
        if let Some((k, v)) = arg.split_once('=') {
            config.insert(k.to_lowercase(), v.to_string());
        }
    }
    let mut cfg = current.clone();
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
            "proof" => strat = proof_mint_strategy(),
            "authority" => strat.mint_behavior = TokenMintBehavior::MintWithAuthority as i32,
            "signature" => strat.mint_behavior = TokenMintBehavior::MintWithSignature as i32,
            "payment" => strat.mint_behavior = TokenMintBehavior::MintWithPayment as i32,
            other => anyhow::bail!("unknown mint strategy: {other}"),
        }
        let unchanged = current
            .mint_strategy
            .as_ref()
            .is_some_and(|s| is_strategy(s, &strat));
        if !unchanged {
            cfg.mint_strategy = Some(strat);
        }
    }
    if let Some(v) = config.get("units") {
        cfg.units = parse_bigint_be(v)?;
    }
    if let Some(v) = config.get("supply") {
        cfg.supply = parse_bigint_be(v)?;
    }
    Ok(cfg)
}

/// Whether `current` is the `requested` strategy: the same mint behavior
/// and proof basis, the fields the args set. Then it keeps its terms
/// (payment address, price, authority, entitlement root), which the args
/// cannot set; otherwise the update takes the requested strategy.
fn is_strategy(current: &TokenMintStrategy, requested: &TokenMintStrategy) -> bool {
    current.mint_behavior == requested.mint_behavior && current.proof_basis == requested.proof_basis
}

/// One `Field: old -> new` line per field the update changes.
fn changed_fields(current: &TokenConfiguration, updated: &TokenConfiguration) -> Vec<String> {
    field_values(current)
        .into_iter()
        .zip(field_values(updated))
        .filter(|((_, old), (_, new))| old != new)
        .map(|((field, old), (_, new))| format!("{field}: {} -> {}", short(&old), short(&new)))
        .collect()
}

/// Every field of a configuration, displayed, in a fixed order.
fn field_values(cfg: &TokenConfiguration) -> Vec<(&'static str, String)> {
    const NONE: &str = "(none)";
    let bytes = |b: &[u8]| {
        if b.is_empty() {
            NONE.to_string()
        } else {
            hex::encode(b)
        }
    };
    let number = |b: &[u8]| {
        if b.is_empty() {
            NONE.to_string()
        } else {
            BigUint::from_bytes_be(b).to_string()
        }
    };
    let text = |s: &str| {
        if s.is_empty() {
            NONE.to_string()
        } else {
            s.to_string()
        }
    };
    let strategy = cfg.mint_strategy.clone().unwrap_or_default();
    let mint = match TokenMintBehavior::try_from(strategy.mint_behavior) {
        Ok(TokenMintBehavior::NoMintBehavior) => NONE.to_string(),
        Ok(TokenMintBehavior::MintWithProof) => "proof".to_string(),
        Ok(TokenMintBehavior::MintWithAuthority) => "authority".to_string(),
        Ok(TokenMintBehavior::MintWithSignature) => "signature".to_string(),
        Ok(TokenMintBehavior::MintWithPayment) => "payment".to_string(),
        Err(_) => format!("unknown ({})", strategy.mint_behavior),
    };
    let proof_basis = match ProofBasisType::try_from(strategy.proof_basis) {
        Ok(ProofBasisType::NoProofBasis) => NONE.to_string(),
        Ok(basis) => basis.as_str_name().to_lowercase(),
        Err(_) => format!("unknown ({})", strategy.proof_basis),
    };
    let authority = match &strategy.authority {
        Some(a) => format!(
            "{} (key type {}, can burn: {})",
            bytes(&a.public_key),
            a.key_type,
            a.can_burn
        ),
        None => NONE.to_string(),
    };
    let price = match &strategy.fee_basis {
        Some(f) if f.r#type == FeeBasisType::PerUnit as i32 => {
            format!("{} per unit", number(&f.baseline))
        }
        Some(f) => format!("{} (fee basis {})", number(&f.baseline), f.r#type),
        None => NONE.to_string(),
    };
    let mut behavior: Vec<&str> = BEHAVIOR_FLAGS
        .iter()
        .filter(|(flag, _)| cfg.behavior & flag != 0)
        .map(|(_, name)| *name)
        .collect();
    let unknown = format!("{:#x}", cfg.behavior & !0x3f);
    if cfg.behavior & !0x3f != 0 {
        behavior.push(&unknown);
    }
    vec![
        ("Name", text(&cfg.name)),
        ("Symbol", text(&cfg.symbol)),
        ("Behavior", text(&behavior.join(","))),
        ("Mint strategy", mint),
        ("Proof basis", proof_basis),
        ("Entitlement root", bytes(&strategy.verkle_root)),
        ("Mint authority", authority),
        ("Payment address", bytes(&strategy.payment_address)),
        ("Price", price),
        ("Units", number(&cfg.units)),
        ("Supply", number(&cfg.supply)),
        (
            "Additional reference",
            bytes(&cfg.additional_reference.concat()),
        ),
        ("Owner key", bytes(&cfg.owner_public_key)),
    ]
}

/// A displayed value with each key-length hex word cut to its ends.
fn short(value: &str) -> String {
    let words: Vec<String> = value
        .split(' ')
        .map(|word| {
            if word.len() > 128 && word.bytes().all(|b| b.is_ascii_hexdigit()) {
                format!("{}…{}", &word[..16], &word[word.len() - 16..])
            } else {
                word.to_string()
            }
        })
        .collect();
    words.join(" ")
}

fn parse_bigint_be(s: &str) -> anyhow::Result<Vec<u8>> {
    let n: BigInt = s
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid integer: {s}"))?;
    if n == BigInt::from(0) {
        return Ok(Vec::new());
    }
    if n.sign() == Sign::Minus {
        anyhow::bail!("negative value: {s}");
    }
    Ok(n.to_bytes_be().1)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use quil_execution::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
    use quil_execution::token_intrinsic::conversions::token_config_from_proto;
    use quil_execution::token_intrinsic::materialize::{
        materialize_token_deploy, materialize_token_deploy_init,
    };
    use quil_types::proto::token::FeeBasis;

    use super::*;

    fn paid_mint_token() -> TokenConfiguration {
        TokenConfiguration {
            behavior: MINTABLE | BURNABLE | ACCEPTABLE,
            mint_strategy: Some(TokenMintStrategy {
                mint_behavior: TokenMintBehavior::MintWithPayment as i32,
                payment_address: vec![0x5a; 32],
                fee_basis: Some(FeeBasis {
                    r#type: FeeBasisType::PerUnit as i32,
                    baseline: vec![0x03, 0xe8],
                }),
                ..Default::default()
            }),
            units: vec![0x01],
            supply: vec![0x27, 0x10],
            name: "Example".into(),
            symbol: "EXM".into(),
            additional_reference: vec![vec![0x7c; 64]],
            owner_public_key: vec![0x33; 897],
        }
    }

    fn state() -> HypergraphState {
        HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_tries::ShaInclusionProver),
        )))
    }

    /// The configuration at `domain`, read from its metadata vertex.
    fn read_back(state: &HypergraphState, domain: &[u8; 32]) -> TokenConfiguration {
        let adds = vertex_adds_discriminator().unwrap();
        let blob = state
            .get(domain, &HYPERGRAPH_METADATA_ADDRESS, &adds)
            .unwrap()
            .unwrap();
        config_from_metadata_vertex(&blob).unwrap()
    }

    /// The node stores units and supply padded, so compare them by value.
    fn same_config(a: &TokenConfiguration, b: &TokenConfiguration) -> bool {
        let value = |v: &[u8]| BigUint::from_bytes_be(v);
        let rest = |c: &TokenConfiguration| TokenConfiguration {
            units: Vec::new(),
            supply: Vec::new(),
            ..c.clone()
        };
        rest(a) == rest(b)
            && value(&a.units) == value(&b.units)
            && value(&a.supply) == value(&b.supply)
    }

    #[test]
    fn update_keeps_what_the_deploy_wrote() {
        let state = state();
        let prover = quil_tries::ShaInclusionProver;
        let deployed = paid_mint_token();
        let canonical = token_config_from_proto(&deployed).unwrap();
        let domain = materialize_token_deploy_init(&state, &canonical, 1, &prover).unwrap();
        let current = read_back(&state, &domain);
        assert!(
            same_config(&current, &deployed),
            "deployed configuration read back changed"
        );

        let updated = updated_config(&current, &["name=Renamed".to_string()]).unwrap();
        let canonical = token_config_from_proto(&updated).unwrap();
        materialize_token_deploy(&state, &domain, &canonical, 2, &prover).unwrap();
        let mut want = deployed;
        want.name = "Renamed".into();
        assert!(
            same_config(&read_back(&state, &domain), &want),
            "update erased unchanged fields"
        );
    }

    #[test]
    fn refuses_a_vertex_without_a_token_configuration() {
        let mut tree = quil_tries::VectorCommitmentTree::new();
        tree.insert(&[0u8], b"not a token", &[], &BigInt::from(11))
            .unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        assert!(config_from_metadata_vertex(&blob).is_err());
        assert!(config_from_metadata_vertex(&[]).is_err());
    }

    #[test]
    fn same_mint_strategy_keeps_its_terms() {
        let current = paid_mint_token();
        let same = updated_config(&current, &["mintstrategy=payment".to_string()]).unwrap();
        assert_eq!(same.mint_strategy, current.mint_strategy);
        let other = updated_config(&current, &["mintstrategy=signature".to_string()]).unwrap();
        assert!(other.mint_strategy.unwrap().payment_address.is_empty());
    }

    #[test]
    fn another_proof_basis_takes_the_requested_one() {
        let args = ["mintstrategy=proof".to_string()];
        let mut unset = paid_mint_token();
        unset.mint_strategy = None;
        let requested = updated_config(&unset, &args)
            .unwrap()
            .mint_strategy
            .unwrap();
        let other_basis = if requested.proof_basis == ProofBasisType::ProofOfMeaningfulWork as i32 {
            ProofBasisType::MerkleEntitlementWithSignature
        } else {
            ProofBasisType::ProofOfMeaningfulWork
        };
        let mut current = paid_mint_token();
        current.mint_strategy = Some(TokenMintStrategy {
            mint_behavior: TokenMintBehavior::MintWithProof as i32,
            proof_basis: other_basis as i32,
            verkle_root: vec![0x2b; 32],
            ..Default::default()
        });
        let updated = updated_config(&current, &args).unwrap();
        assert_eq!(
            updated.mint_strategy,
            Some(requested.clone()),
            "proof basis kept: the update did not take the requested one"
        );

        let same = TokenMintStrategy {
            verkle_root: vec![0x2b; 32],
            ..requested
        };
        current.mint_strategy = Some(same.clone());
        let updated = updated_config(&current, &args).unwrap();
        assert_eq!(
            updated.mint_strategy,
            Some(same),
            "same basis lost its terms"
        );
    }

    #[test]
    fn lists_only_the_changed_fields() {
        let current = paid_mint_token();
        assert!(changed_fields(&current, &current).is_empty());

        let args = [
            "name=Renamed".to_string(),
            "mintstrategy=signature".to_string(),
        ];
        let updated = updated_config(&current, &args).unwrap();
        assert_eq!(
            changed_fields(&current, &updated),
            vec![
                "Name: Example -> Renamed".to_string(),
                "Mint strategy: payment -> signature".to_string(),
                format!("Payment address: {} -> (none)", "5a".repeat(32)),
                "Price: 1000 per unit -> (none)".to_string(),
            ]
        );

        let mut rekeyed = current.clone();
        rekeyed.owner_public_key = vec![0x44; 897];
        let (old, new) = ("33".repeat(8), "44".repeat(8));
        assert_eq!(
            changed_fields(&current, &rekeyed),
            vec![format!("Owner key: {old}…{old} -> {new}…{new}")]
        );
    }
}
