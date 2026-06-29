//! Token RDF hypergraph schema builder — byte-exact port of Go
//! `token_configuration.go` `GenerateRDFPrelude` +
//! `PrepareRDFSchemaFromConfig` (lines 291-458). The produced string is
//! stored RAW at key `[2<<2]` of the deployed token's metadata vertex
//! (see `HypergraphState::init_metadata_vertex`), so it MUST match Go
//! byte-for-byte — every newline and two-space continuation indent is
//! significant to the resulting tree commitment / `state_roots`.

use super::constants::{ACCEPTABLE, DIVISIBLE, EXPIRABLE};

/// Go `GenerateRDFPrelude`. `behavior` is the token's `Behavior` bitfield
/// (`config.behavior`); the `pending:` prefix is emitted only for
/// `Acceptable` tokens.
pub fn generate_rdf_prelude(app_address: &[u8], behavior: u32) -> String {
    let app_hex = hex::encode(app_address);
    let mut s = String::new();
    s.push_str("BASE <https://types.quilibrium.com/schema-repository/>\n");
    s.push_str("PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n");
    s.push_str("PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\n");
    s.push_str("PREFIX qcl: <https://types.quilibrium.com/qcl/>\n");
    s.push_str(&format!(
        "PREFIX coin: <https://types.quilibrium.com/schema-repository/token/{app_hex}/coin/>\n"
    ));
    if behavior & (ACCEPTABLE as u32) != 0 {
        s.push_str(&format!(
            "PREFIX pending: <https://types.quilibrium.com/schema-repository/token/{app_hex}/pending/>\n"
        ));
    }
    s.push('\n');
    s
}

/// Go `PrepareRDFSchemaFromConfig`. Builds the full Turtle RDF schema for
/// a token, templated by `app_address` (hex) and the `Behavior` flags
/// (`Divisible`, `Acceptable`, `Expirable`).
pub fn prepare_rdf_schema_from_config(app_address: &[u8], behavior: u32) -> String {
    let acceptable = behavior & (ACCEPTABLE as u32) != 0;
    let divisible = behavior & (DIVISIBLE as u32) != 0;
    let expirable = behavior & (EXPIRABLE as u32) != 0;

    let mut s = generate_rdf_prelude(app_address, behavior);

    s.push_str(
        "coin:Coin a rdfs:Class.\n\
         coin:FrameNumber a rdfs:Property;\n  \
         rdfs:domain qcl:Uint;\n  \
         qcl:size 8;\n  \
         qcl:order 0;\n  \
         rdfs:range coin:Coin.\n\
         coin:Commitment a rdfs:Property;\n  \
         rdfs:domain qcl:ByteArray;\n  \
         qcl:size 56;\n  \
         qcl:order 1;\n  \
         rdfs:range coin:Coin.\n\
         coin:OneTimeKey a rdfs:Property;\n  \
         rdfs:domain qcl:ByteArray;\n  \
         qcl:size 56;\n  \
         qcl:order 2;\n  \
         rdfs:range coin:Coin.\n\
         coin:VerificationKey a rdfs:Property;\n  \
         rdfs:domain qcl:ByteArray;\n  \
         qcl:size 56;\n  \
         qcl:order 3;\n  \
         rdfs:range coin:Coin.\n\
         coin:CoinBalance a rdfs:Property;\n  \
         rdfs:domain qcl:Uint;\n  \
         qcl:size 56;\n  \
         qcl:order 4;\n  \
         rdfs:range coin:Coin.\n\
         coin:Mask a rdfs:Property;\n  \
         rdfs:domain qcl:ByteArray;\n  \
         qcl:size 56;\n  \
         qcl:order 5;\n  \
         rdfs:range coin:Coin.\n",
    );

    if !divisible {
        s.push_str(
            "coin:AdditionalReference a rdfs:Property;\n  \
             rdfs:domain qcl:ByteArray;\n  \
             qcl:size 64;\n  \
             qcl:order 6;\n  \
             rdfs:range coin:Coin.\n\
             coin:AdditionalReferenceKey a rdfs:Property;\n  \
             rdfs:domain qcl:ByteArray;\n  \
             qcl:size 56;\n  \
             qcl:order 7;\n  \
             rdfs:range coin:Coin.\n",
        );
    }

    if acceptable {
        s.push_str(
            "\npending:PendingTransaction a rdfs:Class;\n  \
             rdfs:label \"a pending transaction\".\n\
             pending:FrameNumber a rdfs:Property;\n  \
             rdfs:domain qcl:Uint;\n  \
             qcl:size 8;\n  \
             qcl:order 0;\n  \
             rdfs:range pending:PendingTransaction.\n\
             pending:Commitment a rdfs:Property;\n  \
             rdfs:domain qcl:ByteArray;\n  \
             qcl:size 56;\n  \
             qcl:order 1;\n  \
             rdfs:range pending:PendingTransaction.\n\
             pending:ToOneTimeKey a rdfs:Property;\n  \
             rdfs:domain qcl:ByteArray;\n  \
             qcl:size 56;\n  \
             qcl:order 2;\n  \
             rdfs:range pending:PendingTransaction.\n\
             pending:RefundOneTimeKey a rdfs:Property;\n  \
             rdfs:domain qcl:ByteArray;\n  \
             qcl:size 56;\n  \
             qcl:order 3;\n  \
             rdfs:range pending:PendingTransaction.\n\
             pending:ToVerificationKey a rdfs:Property;\n  \
             rdfs:domain qcl:ByteArray;\n  \
             qcl:size 56;\n  \
             qcl:order 4;\n  \
             rdfs:range pending:PendingTransaction.\n\
             pending:RefundVerificationKey a rdfs:Property;\n  \
             rdfs:domain qcl:ByteArray;\n  \
             qcl:size 56;\n  \
             qcl:order 5;\n  \
             rdfs:range pending:PendingTransaction.\n\
             pending:ToCoinBalance a rdfs:Property;\n  \
             rdfs:domain qcl:Uint;\n  \
             qcl:size 56;\n  \
             qcl:order 6;\n  \
             rdfs:range pending:PendingTransaction.\n\
             pending:RefundCoinBalance a rdfs:Property;\n  \
             rdfs:domain qcl:Uint;\n  \
             qcl:size 56;\n  \
             qcl:order 7;\n  \
             rdfs:range pending:PendingTransaction.\n\
             pending:ToMask a rdfs:Property;\n  \
             rdfs:domain qcl:ByteArray;\n  \
             qcl:size 56;\n  \
             qcl:order 8;\n  \
             rdfs:range pending:PendingTransaction.\n\
             pending:RefundMask a rdfs:Property;\n  \
             rdfs:domain qcl:ByteArray;\n  \
             qcl:size 56;\n  \
             qcl:order 9;\n  \
             rdfs:range pending:PendingTransaction.\n",
        );

        if !divisible {
            s.push_str(
                "pending:ToAdditionalReference a rdfs:Property;\n  \
                 rdfs:domain qcl:ByteArray;\n  \
                 qcl:size 64;\n  \
                 qcl:order 10;\n  \
                 rdfs:range pending:PendingTransaction.\n\
                 pending:ToAdditionalReferenceKey a rdfs:Property;\n  \
                 rdfs:domain qcl:ByteArray;\n  \
                 qcl:size 56;\n  \
                 qcl:order 11;\n  \
                 rdfs:range pending:PendingTransaction.\n\
                 pending:RefundAdditionalReference a rdfs:Property;\n  \
                 rdfs:domain qcl:ByteArray;\n  \
                 qcl:size 64;\n  \
                 qcl:order 12;\n  \
                 rdfs:range pending:PendingTransaction.\n\
                 pending:RefundAdditionalReferenceKey a rdfs:Property;\n  \
                 rdfs:domain qcl:ByteArray;\n  \
                 qcl:size 56;\n  \
                 qcl:order 13;\n  \
                 rdfs:range pending:PendingTransaction.\n",
            );
        }

        if expirable {
            s.push_str(
                "pending:Expiration a rdfs:Property;\n  \
                 rdfs:domain qcl:Uint;\n  \
                 qcl:size 8;\n",
            );
            if !divisible {
                s.push_str("  qcl:order 14;\n");
            } else {
                s.push_str("  qcl:order 10;\n");
            }
            s.push_str("  rdfs:range pending:PendingTransaction.\n");
        }
    }

    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    // Rebuild the Go schema literally from the Go source (token_configuration.go)
    // for a divisible+acceptable+expirable token (QUIL behavior) and a
    // non-divisible variant, to lock byte-parity.
    fn go_prelude(app_hex: &str, acceptable: bool) -> String {
        let mut s = String::new();
        s.push_str("BASE <https://types.quilibrium.com/schema-repository/>\n");
        s.push_str("PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>\n");
        s.push_str("PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>\n");
        s.push_str("PREFIX qcl: <https://types.quilibrium.com/qcl/>\n");
        s.push_str(&format!(
            "PREFIX coin: <https://types.quilibrium.com/schema-repository/token/{app_hex}/coin/>\n"
        ));
        if acceptable {
            s.push_str(&format!("PREFIX pending: <https://types.quilibrium.com/schema-repository/token/{app_hex}/pending/>\n"));
        }
        s.push('\n');
        s
    }

    #[test]
    fn prelude_includes_pending_only_when_acceptable() {
        let addr = [0xABu8; 32];
        let hex_addr = hex::encode(addr);
        assert_eq!(
            generate_rdf_prelude(&addr, ACCEPTABLE as u32),
            go_prelude(&hex_addr, true)
        );
        // Mintable-only (no Acceptable) → no pending prefix.
        assert_eq!(
            generate_rdf_prelude(&addr, 0),
            go_prelude(&hex_addr, false)
        );
    }

    #[test]
    fn divisible_token_omits_additional_reference() {
        let addr = [0x01u8; 32];
        let s = prepare_rdf_schema_from_config(&addr, DIVISIBLE as u32);
        assert!(s.contains("coin:Coin a rdfs:Class."));
        assert!(s.contains("coin:Mask a rdfs:Property;"));
        // Divisible → no AdditionalReference coin fields.
        assert!(!s.contains("coin:AdditionalReference "));
        // Not Acceptable → no pending class.
        assert!(!s.contains("pending:PendingTransaction"));
        assert!(s.ends_with("rdfs:range coin:Coin.\n\n"));
    }

    #[test]
    fn non_divisible_includes_additional_reference() {
        let addr = [0x02u8; 32];
        let s = prepare_rdf_schema_from_config(&addr, 0);
        assert!(s.contains(
            "coin:AdditionalReference a rdfs:Property;\n  rdfs:domain qcl:ByteArray;\n  qcl:size 64;\n  qcl:order 6;\n  rdfs:range coin:Coin.\n"
        ));
        assert!(s.contains("coin:AdditionalReferenceKey a rdfs:Property;"));
    }

    #[test]
    fn acceptable_expirable_divisible_orders_expiration_at_10() {
        let addr = [0x03u8; 32];
        let b = (ACCEPTABLE as u32) | (EXPIRABLE as u32) | (DIVISIBLE as u32);
        let s = prepare_rdf_schema_from_config(&addr, b);
        assert!(s.contains("pending:PendingTransaction a rdfs:Class;"));
        // Divisible → no pending AdditionalReference (orders 10-13); Expiration at order 10.
        assert!(!s.contains("pending:ToAdditionalReference "));
        assert!(s.contains("pending:Expiration a rdfs:Property;\n  rdfs:domain qcl:Uint;\n  qcl:size 8;\n  qcl:order 10;\n  rdfs:range pending:PendingTransaction.\n"));
    }

    /// TRUE byte-parity vectors captured by running Go's
    /// `PrepareRDFSchemaFromConfig` (node/execution/intrinsics/token,
    /// `rdf_vector_test.go`, linked against the FFI staticlibs via
    /// build_go.sh) for app address `0x42*32`. Non-circular: these bytes
    /// were produced by Go, not reconstructed from the Rust port — so
    /// they catch any template divergence the Rust port might share with
    /// a misreading of the Go source.
    #[test]
    fn rdf_schema_matches_go_vectors() {
        let domain = [0x42u8; 32];

        // Behavior = Divisible | Acceptable | Expirable (4|8|16).
        let go_dae_hex = "42415345203c68747470733a2f2f74797065732e7175696c69627269756d2e636f6d2f736368656d612d7265706f7369746f72792f3e0a505245464958207264663a203c687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e73233e0a50524546495820726466733a203c687474703a2f2f7777772e77332e6f72672f323030302f30312f7264662d736368656d61233e0a5052454649582071636c3a203c68747470733a2f2f74797065732e7175696c69627269756d2e636f6d2f71636c2f3e0a50524546495820636f696e3a203c68747470733a2f2f74797065732e7175696c69627269756d2e636f6d2f736368656d612d7265706f7369746f72792f746f6b656e2f343234323432343234323432343234323432343234323432343234323432343234323432343234323432343234323432343234323432343234323432343234322f636f696e2f3e0a5052454649582070656e64696e673a203c68747470733a2f2f74797065732e7175696c69627269756d2e636f6d2f736368656d612d7265706f7369746f72792f746f6b656e2f343234323432343234323432343234323432343234323432343234323432343234323432343234323432343234323432343234323432343234323432343234322f70656e64696e672f3e0a0a636f696e3a436f696e206120726466733a436c6173732e0a636f696e3a4672616d654e756d626572206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a55696e743b0a202071636c3a73697a6520383b0a202071636c3a6f7264657220303b0a2020726466733a72616e676520636f696e3a436f696e2e0a636f696e3a436f6d6d69746d656e74206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220313b0a2020726466733a72616e676520636f696e3a436f696e2e0a636f696e3a4f6e6554696d654b6579206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220323b0a2020726466733a72616e676520636f696e3a436f696e2e0a636f696e3a566572696669636174696f6e4b6579206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220333b0a2020726466733a72616e676520636f696e3a436f696e2e0a636f696e3a436f696e42616c616e6365206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a55696e743b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220343b0a2020726466733a72616e676520636f696e3a436f696e2e0a636f696e3a4d61736b206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220353b0a2020726466733a72616e676520636f696e3a436f696e2e0a0a70656e64696e673a50656e64696e675472616e73616374696f6e206120726466733a436c6173733b0a2020726466733a6c6162656c2022612070656e64696e67207472616e73616374696f6e222e0a70656e64696e673a4672616d654e756d626572206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a55696e743b0a202071636c3a73697a6520383b0a202071636c3a6f7264657220303b0a2020726466733a72616e67652070656e64696e673a50656e64696e675472616e73616374696f6e2e0a70656e64696e673a436f6d6d69746d656e74206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220313b0a2020726466733a72616e67652070656e64696e673a50656e64696e675472616e73616374696f6e2e0a70656e64696e673a546f4f6e6554696d654b6579206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220323b0a2020726466733a72616e67652070656e64696e673a50656e64696e675472616e73616374696f6e2e0a70656e64696e673a526566756e644f6e6554696d654b6579206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220333b0a2020726466733a72616e67652070656e64696e673a50656e64696e675472616e73616374696f6e2e0a70656e64696e673a546f566572696669636174696f6e4b6579206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220343b0a2020726466733a72616e67652070656e64696e673a50656e64696e675472616e73616374696f6e2e0a70656e64696e673a526566756e64566572696669636174696f6e4b6579206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220353b0a2020726466733a72616e67652070656e64696e673a50656e64696e675472616e73616374696f6e2e0a70656e64696e673a546f436f696e42616c616e6365206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a55696e743b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220363b0a2020726466733a72616e67652070656e64696e673a50656e64696e675472616e73616374696f6e2e0a70656e64696e673a526566756e64436f696e42616c616e6365206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a55696e743b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220373b0a2020726466733a72616e67652070656e64696e673a50656e64696e675472616e73616374696f6e2e0a70656e64696e673a546f4d61736b206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220383b0a2020726466733a72616e67652070656e64696e673a50656e64696e675472616e73616374696f6e2e0a70656e64696e673a526566756e644d61736b206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220393b0a2020726466733a72616e67652070656e64696e673a50656e64696e675472616e73616374696f6e2e0a70656e64696e673a45787069726174696f6e206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a55696e743b0a202071636c3a73697a6520383b0a202071636c3a6f726465722031303b0a2020726466733a72616e67652070656e64696e673a50656e64696e675472616e73616374696f6e2e0a0a";
        let go_dae = hex::decode(go_dae_hex).unwrap();
        let rust_dae = prepare_rdf_schema_from_config(
            &domain,
            (DIVISIBLE | ACCEPTABLE | EXPIRABLE) as u32,
        );
        assert_eq!(rust_dae.as_bytes(), &go_dae[..], "Divisible|Acceptable|Expirable");

        // Behavior = Mintable only (non-divisible, no pending, no expiration).
        let go_m_hex = "42415345203c68747470733a2f2f74797065732e7175696c69627269756d2e636f6d2f736368656d612d7265706f7369746f72792f3e0a505245464958207264663a203c687474703a2f2f7777772e77332e6f72672f313939392f30322f32322d7264662d73796e7461782d6e73233e0a50524546495820726466733a203c687474703a2f2f7777772e77332e6f72672f323030302f30312f7264662d736368656d61233e0a5052454649582071636c3a203c68747470733a2f2f74797065732e7175696c69627269756d2e636f6d2f71636c2f3e0a50524546495820636f696e3a203c68747470733a2f2f74797065732e7175696c69627269756d2e636f6d2f736368656d612d7265706f7369746f72792f746f6b656e2f343234323432343234323432343234323432343234323432343234323432343234323432343234323432343234323432343234323432343234323432343234322f636f696e2f3e0a0a636f696e3a436f696e206120726466733a436c6173732e0a636f696e3a4672616d654e756d626572206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a55696e743b0a202071636c3a73697a6520383b0a202071636c3a6f7264657220303b0a2020726466733a72616e676520636f696e3a436f696e2e0a636f696e3a436f6d6d69746d656e74206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220313b0a2020726466733a72616e676520636f696e3a436f696e2e0a636f696e3a4f6e6554696d654b6579206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220323b0a2020726466733a72616e676520636f696e3a436f696e2e0a636f696e3a566572696669636174696f6e4b6579206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220333b0a2020726466733a72616e676520636f696e3a436f696e2e0a636f696e3a436f696e42616c616e6365206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a55696e743b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220343b0a2020726466733a72616e676520636f696e3a436f696e2e0a636f696e3a4d61736b206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220353b0a2020726466733a72616e676520636f696e3a436f696e2e0a636f696e3a4164646974696f6e616c5265666572656e6365206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652036343b0a202071636c3a6f7264657220363b0a2020726466733a72616e676520636f696e3a436f696e2e0a636f696e3a4164646974696f6e616c5265666572656e63654b6579206120726466733a50726f70657274793b0a2020726466733a646f6d61696e2071636c3a4279746541727261793b0a202071636c3a73697a652035363b0a202071636c3a6f7264657220373b0a2020726466733a72616e676520636f696e3a436f696e2e0a0a";
        let go_m = hex::decode(go_m_hex).unwrap();
        let rust_m = prepare_rdf_schema_from_config(&domain, super::super::constants::MINTABLE as u32);
        assert_eq!(rust_m.as_bytes(), &go_m[..], "Mintable only");
    }

    #[test]
    fn acceptable_expirable_nondivisible_orders_expiration_at_14() {
        let addr = [0x04u8; 32];
        let b = (ACCEPTABLE as u32) | (EXPIRABLE as u32);
        let s = prepare_rdf_schema_from_config(&addr, b);
        assert!(s.contains("pending:ToAdditionalReference a rdfs:Property;"));
        assert!(s.contains("pending:RefundAdditionalReferenceKey a rdfs:Property;\n  rdfs:domain qcl:ByteArray;\n  qcl:size 56;\n  qcl:order 13;\n  rdfs:range pending:PendingTransaction.\n"));
        assert!(s.contains("pending:Expiration a rdfs:Property;\n  rdfs:domain qcl:Uint;\n  qcl:size 8;\n  qcl:order 14;\n  rdfs:range pending:PendingTransaction.\n"));
    }
}
