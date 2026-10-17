#[test]
fn client_derived_token_domain_matches_the_node_path() {
    use quil_types::proto::token::{TokenConfiguration, TokenMintStrategy, TokenMintBehavior, Authority};
    let cfg = TokenConfiguration {
        behavior: 1 | 4,
        mint_strategy: Some(TokenMintStrategy {
            mint_behavior: TokenMintBehavior::MintWithAuthority as i32,
            proof_basis: 0, verkle_root: vec![],
            authority: Some(Authority { key_type: 8, public_key: vec![0xAB; 897], can_burn: false }),
            payment_address: vec![], fee_basis: None,
        }),
        name: "SettledAuth".into(), symbol: "SAU".into(),
        units: vec![], supply: vec![], additional_reference: vec![],
        owner_public_key: vec![0xCD; 897],
    };
    // Client: proto -> canonical config -> domain.
    let client = quil_execution::token_intrinsic::materialize::token_deploy_domain(
        &quil_execution::token_intrinsic::conversions::token_config_from_proto(&cfg).unwrap()).unwrap();
    // Node: the wire bundle's canonical bytes -> TokenDeploy -> config -> domain.
    let request = quil_types::proto::global::MessageRequest {
        request: Some(quil_types::proto::global::message_request::Request::TokenDeploy(
            quil_types::proto::token::TokenDeploy { config: Some(cfg.clone()), rdf_schema: Vec::new() })),
        timestamp: 0,
    };
    let inner = quil_execution::message_envelope::proto_message_request_to_canonical_inner_bytes(&request).unwrap();
    let deploy = quil_execution::token_intrinsic::TokenDeploy::from_canonical_bytes(&inner).unwrap();
    let node_cfg = quil_execution::token_intrinsic::TokenConfiguration::from_canonical_bytes(&deploy.config).unwrap();
    let node = quil_execution::token_intrinsic::materialize::token_deploy_domain(&node_cfg).unwrap();
    assert_eq!(hex::encode(client), hex::encode(node), "client and node derive different token domains");
}
