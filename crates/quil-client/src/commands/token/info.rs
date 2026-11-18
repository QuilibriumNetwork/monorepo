//! `qclient token info <TokenDomain>`: a token's name, symbol and
//! configuration, read from its metadata vertex (`domain ‖
//! HYPERGRAPH_METADATA_ADDRESS`), the record its deploy and updates write.

use num_bigint::BigUint;
use tonic::transport::Channel;

use quil_execution::hypergraph_intrinsic::hypergraph_base_domain;
use quil_execution::hypergraph_state::HYPERGRAPH_METADATA_ADDRESS;
use quil_execution::token_intrinsic::config::TokenConfiguration;
use quil_execution::token_intrinsic::constants::token_base_domain;
use quil_execution::token_intrinsic::conversions::token_config_to_proto;
use quil_execution::token_intrinsic::materialize::TOKEN_CONFIG_OUTER_KEY;
use quil_execution::token_intrinsic::metadata_schema::decode_token_config_from_tree;
use quil_types::crypto::KeyType;
use quil_types::proto::node::node_service_client::NodeServiceClient;
use quil_types::proto::node::GetVertexDataRequest;
use quil_types::proto::token::{FeeBasisType, ProofBasisType, TokenMintBehavior};

use super::TokenCtx;

/// The metadata vertex key holding the base domain of the intrinsic that
/// deployed the application (`init_metadata_vertex`).
const TYPE_DOMAIN_KEY: [u8; 32] = [0xFF; 32];

const BEHAVIOR_FLAGS: [(u32, &str); 6] = [
    (1 << 0, "mintable"),
    (1 << 1, "burnable"),
    (1 << 2, "divisible"),
    (1 << 3, "acceptable"),
    (1 << 4, "expirable"),
    (1 << 5, "tenderable"),
];

pub(crate) async fn run(tc: &TokenCtx, domain: &str) -> anyhow::Result<()> {
    let domain: [u8; 32] = hex::decode(domain.strip_prefix("0x").unwrap_or(domain))
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("{domain:?} is not a token domain (32 bytes of hex)"))?;
    let shown = hex::encode(domain);
    let mut client = tc.connect().await?;
    let blob = metadata_vertex(&mut client, &domain)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no metadata vertex for {shown}: no token or application is deployed there"
            )
        })?;
    let config =
        token_config_from_metadata_vertex(&blob).map_err(|e| anyhow::anyhow!("{shown}: {e}"))?;
    println!("Domain: {shown}");
    for line in info_lines(&config)? {
        println!("{line}");
    }
    Ok(())
}

/// The serialized metadata vertex of `domain`; `None` when the node holds
/// none.
pub(crate) async fn metadata_vertex(
    client: &mut NodeServiceClient<Channel>,
    domain: &[u8; 32],
) -> anyhow::Result<Option<Vec<u8>>> {
    let mut address = domain.to_vec();
    address.extend_from_slice(&HYPERGRAPH_METADATA_ADDRESS);
    let response = client
        .get_vertex_data(tonic::Request::new(GetVertexDataRequest {
            address,
            full_data: true,
        }))
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "could not read the metadata vertex of {}: {e}",
                hex::encode(domain)
            )
        })?
        .into_inner();
    let present = response.present != Some(false) && !response.raw_data.is_empty();
    Ok(present.then_some(response.raw_data))
}

/// Decode the token configuration from a metadata vertex. A vertex that
/// another intrinsic deployed, or that holds no configuration, is refused.
pub(crate) fn token_config_from_metadata_vertex(blob: &[u8]) -> anyhow::Result<TokenConfiguration> {
    let outer = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(blob)
            .map_err(|e| anyhow::anyhow!("metadata vertex: {e}"))?,
    };
    match outer.get(&TYPE_DOMAIN_KEY) {
        Some(kind) if kind == hypergraph_base_domain().as_slice() => {
            anyhow::bail!("not a token: a hypergraph app")
        }
        Some(kind) if kind != token_base_domain().as_slice() => {
            anyhow::bail!("no token configuration")
        }
        _ => {}
    }
    let inner_blob = outer
        .get(&TOKEN_CONFIG_OUTER_KEY)
        .ok_or_else(|| anyhow::anyhow!("no token configuration"))?;
    let inner = quil_tries::VectorCommitmentTree {
        root: quil_tries::deserialize_go_tree(inner_blob)
            .map_err(|e| anyhow::anyhow!("token configuration: {e}"))?,
    };
    decode_token_config_from_tree(&inner).map_err(|e| anyhow::anyhow!("token configuration: {e}"))
}

/// One `Field: value` line per field: name, symbol, units, supply, behavior
/// and mint strategy always, the strategy's terms and the additional
/// reference where set.
pub(crate) fn info_lines(cfg: &TokenConfiguration) -> anyhow::Result<Vec<String>> {
    let proto =
        token_config_to_proto(cfg).map_err(|e| anyhow::anyhow!("token configuration: {e}"))?;
    let strategy = proto.mint_strategy.unwrap_or_default();
    let mut lines = vec![
        format!("Name: {}", text(&cfg.name)),
        format!("Symbol: {}", text(&cfg.symbol)),
        format!("Units: {}", number(&cfg.units)),
        format!("Supply: {}", number(&cfg.supply)),
        format!("Behavior: {}", behavior(cfg.behavior)),
        format!("Mint strategy: {}", mint_behavior(strategy.mint_behavior)),
    ];
    let mut field = |name: &str, value: String| lines.push(format!("{name}: {value}"));
    if strategy.proof_basis != ProofBasisType::NoProofBasis as i32 {
        let basis = match ProofBasisType::try_from(strategy.proof_basis) {
            Ok(basis) => basis.as_str_name().to_lowercase().replace('_', " "),
            Err(_) => format!("unknown ({})", strategy.proof_basis),
        };
        field("Proof basis", basis);
    }
    if !strategy.verkle_root.is_empty() {
        field("Entitlement root", hex::encode(&strategy.verkle_root));
    }
    if let Some(authority) = &strategy.authority {
        let kind = if authority.key_type == KeyType::Falcon512 as u32 {
            "Falcon-512".to_string()
        } else {
            format!("key type {}", authority.key_type)
        };
        let burn = if authority.can_burn { "yes" } else { "no" };
        let key = short_hex(&authority.public_key);
        let value = format!("{key} ({kind}, can burn: {burn})");
        field("Mint authority", value);
    }
    if !strategy.payment_address.is_empty() {
        field("Payment address", hex::encode(&strategy.payment_address));
    }
    if let Some(fee) = &strategy.fee_basis {
        if fee.r#type == FeeBasisType::PerUnit as i32 {
            let price = format!("{} QUIL base units per unit", number(&fee.baseline));
            field("Price", price);
        } else if fee.r#type != FeeBasisType::NoFeeBasis as i32 || !fee.baseline.is_empty() {
            let basis = format!("type {}, baseline {}", fee.r#type, number(&fee.baseline));
            field("Fee basis", basis);
        }
    }
    let reference = cfg.additional_reference.concat();
    if !reference.is_empty() {
        field("Additional reference", hex::encode(reference));
    }
    Ok(lines)
}

/// Text from the chain, printed safely: as stored when it is UTF-8 without
/// control or invisible formatting characters, with those escaped when it
/// has them, and as hex when it is not UTF-8 (a name cut at its 64-byte
/// limit can split a character).
fn text(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "none".to_string();
    }
    match std::str::from_utf8(bytes) {
        Ok(s) if !s.chars().any(hidden) => s.to_string(),
        Ok(s) => {
            let escaped: String = s
                .chars()
                .map(|c| {
                    if hidden(c) {
                        c.escape_unicode().to_string()
                    } else {
                        c.to_string()
                    }
                })
                .collect();
            format!("{escaped} (escaped)")
        }
        Err(_) => format!("0x{} (not UTF-8)", hex::encode(bytes)),
    }
}

/// A character a terminal would act on or not show: controls, and the
/// zero-width and bidirectional formatting characters.
fn hidden(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2069}'
                | '\u{feff}'
        )
}

fn number(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "none".to_string()
    } else {
        BigUint::from_bytes_be(bytes).to_string()
    }
}

fn behavior(bits: u32) -> String {
    let known = BEHAVIOR_FLAGS.iter().fold(0, |all, (flag, _)| all | flag);
    let mut names: Vec<String> = BEHAVIOR_FLAGS
        .iter()
        .filter(|(flag, _)| bits & flag != 0)
        .map(|(_, name)| name.to_string())
        .collect();
    if bits & !known != 0 {
        names.push(format!("{:#x}", bits & !known));
    }
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join(", ")
    }
}

/// The strategy's name as `deploy token mintstrategy=` takes it.
fn mint_behavior(value: i32) -> String {
    match TokenMintBehavior::try_from(value) {
        Ok(TokenMintBehavior::NoMintBehavior) => "none".to_string(),
        Ok(TokenMintBehavior::MintWithProof) => "proof".to_string(),
        Ok(TokenMintBehavior::MintWithAuthority) => "authority".to_string(),
        Ok(TokenMintBehavior::MintWithSignature) => "signature".to_string(),
        Ok(TokenMintBehavior::MintWithPayment) => "payment".to_string(),
        Err(_) => format!("unknown ({value})"),
    }
}

/// A key as hex, cut to its first and last 8 bytes when longer than 64.
fn short_hex(bytes: &[u8]) -> String {
    if bytes.len() > 64 {
        format!(
            "{}…{}",
            hex::encode(&bytes[..8]),
            hex::encode(&bytes[bytes.len() - 8..])
        )
    } else {
        hex::encode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use num_bigint::BigInt;

    use quil_execution::hypergraph_intrinsic::{
        materialize_hypergraph_deploy_init, HypergraphConfiguration,
    };
    use quil_execution::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
    use quil_execution::token_intrinsic::conversions::token_config_from_proto;
    use quil_execution::token_intrinsic::materialize::materialize_token_deploy_init;
    use quil_types::proto::token::{
        Authority, FeeBasis, TokenConfiguration as ProtoConfiguration, TokenMintStrategy,
    };

    use super::*;

    fn state() -> HypergraphState {
        HypergraphState::new(Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_tries::ShaInclusionProver),
        )))
    }

    /// The metadata vertex a token deploy of `config` writes.
    fn deployed(config: &TokenConfiguration) -> Vec<u8> {
        let state = state();
        let domain =
            materialize_token_deploy_init(&state, config, 1, &quil_tries::ShaInclusionProver)
                .unwrap();
        metadata(&state, &domain)
    }

    fn metadata(state: &HypergraphState, domain: &[u8; 32]) -> Vec<u8> {
        let adds = vertex_adds_discriminator().unwrap();
        state
            .get(domain, &HYPERGRAPH_METADATA_ADDRESS, &adds)
            .unwrap()
            .unwrap()
    }

    fn lines_of(blob: &[u8]) -> Vec<String> {
        let config = token_config_from_metadata_vertex(blob)
            .unwrap_or_else(|e| panic!("token info: read failed: {e}"));
        info_lines(&config).unwrap_or_else(|e| panic!("token info: display failed: {e}"))
    }

    /// A token with every configuration field set.
    fn every_field() -> TokenConfiguration {
        token_config_from_proto(&ProtoConfiguration {
            // The six flags and one bit no flag names.
            behavior: 0x7f,
            mint_strategy: Some(TokenMintStrategy {
                mint_behavior: TokenMintBehavior::MintWithPayment as i32,
                proof_basis: ProofBasisType::MerkleEntitlementWithSignature as i32,
                verkle_root: vec![0x11; 32],
                authority: Some(Authority {
                    key_type: KeyType::Falcon512 as u32,
                    public_key: vec![0x22; 897],
                    can_burn: true,
                }),
                payment_address: vec![0x5a; 32],
                fee_basis: Some(FeeBasis {
                    r#type: FeeBasisType::PerUnit as i32,
                    baseline: vec![0x03, 0xe8],
                }),
            }),
            units: vec![0x01],
            supply: vec![0x27, 0x10],
            name: "Example".into(),
            symbol: "EXM".into(),
            additional_reference: vec![vec![0x7c; 64]],
            owner_public_key: vec![0x33; 897],
        })
        .unwrap()
    }

    #[test]
    fn token_info_prints_every_field() {
        let want = vec![
            "Name: Example".to_string(),
            "Symbol: EXM".to_string(),
            "Units: 1".to_string(),
            "Supply: 10000".to_string(),
            "Behavior: mintable, burnable, divisible, acceptable, expirable, tenderable, 0x40"
                .to_string(),
            "Mint strategy: payment".to_string(),
            "Proof basis: merkle entitlement with signature".to_string(),
            format!("Entitlement root: {}", "11".repeat(32)),
            format!(
                "Mint authority: {}…{} (Falcon-512, can burn: yes)",
                "22".repeat(8),
                "22".repeat(8)
            ),
            format!("Payment address: {}", "5a".repeat(32)),
            "Price: 1000 QUIL base units per unit".to_string(),
            format!("Additional reference: {}", "7c".repeat(64)),
        ];
        assert_eq!(
            lines_of(&deployed(&every_field())),
            want,
            "token info: printed configuration"
        );
    }

    #[test]
    fn token_info_refuses_a_hypergraph_app() {
        let state = state();
        let config = HypergraphConfiguration {
            read_public_key: vec![0x01; 57],
            write_public_key: vec![0x02; 57],
            owner_public_key: Vec::new(),
        };
        let domain = materialize_hypergraph_deploy_init(
            &state,
            &config,
            b"@prefix qcl: <https://types.quilibrium.com/qcl/> .",
            1,
            &quil_tries::ShaInclusionProver,
        )
        .unwrap();
        let refusal = |blob: &[u8]| match token_config_from_metadata_vertex(blob) {
            Ok(_) => panic!("token info: read a token configuration"),
            Err(e) => e.to_string(),
        };
        assert_eq!(
            refusal(&metadata(&state, &domain)),
            "not a token: a hypergraph app",
            "token info: hypergraph app refusal"
        );

        // A vertex with neither an intrinsic type nor a configuration.
        let mut tree = quil_tries::VectorCommitmentTree::new();
        tree.insert(&[0u8], b"not a token", &[], &BigInt::from(11))
            .unwrap();
        let blob = quil_tries::serialize_go_tree(tree.root.as_ref()).unwrap();
        assert_eq!(
            refusal(&blob),
            "no token configuration",
            "token info: refusal without a configuration"
        );
    }

    #[test]
    fn token_info_escapes_a_name_that_is_not_text() {
        let mut config = every_field();
        // Not UTF-8, with a terminal escape inside.
        config.name = vec![b'B', 0xff, 0x1b, b'['];
        // UTF-8 with a terminal escape and a right-to-left override.
        config.symbol = "\u{1b}[2J\u{202e}X".as_bytes().to_vec();
        let lines = lines_of(&deployed(&config));
        assert_eq!(
            lines[..2],
            [
                "Name: 0x42ff1b5b (not UTF-8)".to_string(),
                "Symbol: \\u{1b}[2J\\u{202e}X (escaped)".to_string(),
            ],
            "token info: name and symbol"
        );
        assert!(
            lines.iter().all(|line| !line.chars().any(hidden)),
            "token info: a control character printed raw: {lines:?}"
        );
    }
}
