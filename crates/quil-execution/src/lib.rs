pub mod canonical_cursor;
pub mod compute_engine;
pub mod compute_intrinsic;
pub mod engines;
pub mod fees;
pub mod global_engine;
pub mod global_intrinsic;
pub mod global_schema;
pub mod hypergraph_engine;
pub mod hypergraph_intrinsic;
pub mod hypergraph_state;
pub mod intrinsics;
pub mod manager;
pub mod metrics;
pub mod message_envelope;
pub mod prover_registry;
pub mod seniority_compat;
#[cfg(any(test, feature = "testing-stubs"))]
pub mod testing;
pub mod token_engine;
pub mod token_intrinsic;
pub mod traversal_proof;
pub mod turtle;

pub use engines::{EngineType, ExecutionMode};
pub use global_schema::{
    class_def, class_for_type_hash, compute_type_hash, field_key, field_tag, order_to_key,
    ClassDef, FieldTag, RdfType, GLOBAL_CLASSES, GLOBAL_INTRINSIC_ADDRESS, GLOBAL_MAX_ORDER,
    TYPE_HASH_ALLOCATION, TYPE_HASH_PROVER, TYPE_HASH_REWARD, TYPE_HASH_TABLE,
};
pub use manager::ExecutionEngineManager;
pub use prover_registry::{InMemoryProverRegistry, SharedProverRegistry};

/// Well-known domain addresses for execution engines.
pub mod domains {
    /// Global intrinsic address (all 0xFF). Alias for
    /// [`global_schema::GLOBAL_INTRINSIC_ADDRESS`].
    pub use crate::global_schema::GLOBAL_INTRINSIC_ADDRESS as GLOBAL;

    /// Compute intrinsic domain (all 0xCC).
    pub const COMPUTE: [u8; 32] = [0xCC; 32];

    /// QUIL token address (poseidon("q_mainnet_token")).
    pub const QUIL_TOKEN: [u8; 32] = [
        0x11, 0x55, 0x85, 0x84, 0xaf, 0x70, 0x17, 0xa9,
        0xbf, 0xd1, 0xff, 0x18, 0x64, 0x30, 0x2d, 0x64,
        0x3f, 0xbe, 0x58, 0xc6, 0x2d, 0xcf, 0x90, 0xcb,
        0xcd, 0x8f, 0xde, 0x74, 0xa2, 0x67, 0x94, 0xd9,
    ];
}

/// Protocol capability identifiers.
pub mod capabilities {
    pub const GLOBAL_PROTOCOL_V1: u32 = 0x00020001;
    pub const COMPUTE_PROTOCOL_V1: u32 = 0x00010001;
    pub const TOKEN_PROTOCOL_V1: u32 = 0x00040001;
    pub const ARCHIVE_PROTOCOL_V1: u32 = 0x00050001;
}

#[cfg(test)]
mod tests {
    use super::*;

    // =================================================================
    // Domain constants
    // =================================================================

    #[test]
    fn global_domain_is_all_0xff() {
        assert_eq!(domains::GLOBAL, [0xFFu8; 32]);
    }

    #[test]
    fn compute_domain_is_all_0xcc() {
        assert_eq!(domains::COMPUTE, [0xCCu8; 32]);
    }

    #[test]
    fn quil_token_domain_is_32_bytes() {
        assert_eq!(domains::QUIL_TOKEN.len(), 32);
    }

    #[test]
    fn domain_constants_are_distinct() {
        assert_ne!(domains::GLOBAL, domains::COMPUTE);
        assert_ne!(domains::GLOBAL, domains::QUIL_TOKEN);
        assert_ne!(domains::COMPUTE, domains::QUIL_TOKEN);
    }

    #[test]
    fn quil_token_first_bytes_match_mainnet_hash() {
        // First 8 bytes of poseidon("q_mainnet_token"). Locking this
        // prevents any future schema rename from silently drifting the
        // mainnet token address.
        assert_eq!(
            &domains::QUIL_TOKEN[..8],
            &[0x11, 0x55, 0x85, 0x84, 0xaf, 0x70, 0x17, 0xa9]
        );
    }

    // =================================================================
    // Capability identifiers
    // =================================================================

    #[test]
    fn global_protocol_v1_matches_go_constant() {
        assert_eq!(capabilities::GLOBAL_PROTOCOL_V1, 0x00020001);
    }

    #[test]
    fn compute_protocol_v1_matches_go_constant() {
        assert_eq!(capabilities::COMPUTE_PROTOCOL_V1, 0x00010001);
    }

    #[test]
    fn token_protocol_v1_matches_go_constant() {
        assert_eq!(capabilities::TOKEN_PROTOCOL_V1, 0x00040001);
    }

    #[test]
    fn archive_protocol_v1_matches_go_constant() {
        assert_eq!(capabilities::ARCHIVE_PROTOCOL_V1, 0x00050001);
    }

    #[test]
    fn all_capability_ids_are_distinct() {
        use std::collections::HashSet;
        let ids: HashSet<u32> = [
            capabilities::GLOBAL_PROTOCOL_V1,
            capabilities::COMPUTE_PROTOCOL_V1,
            capabilities::TOKEN_PROTOCOL_V1,
            capabilities::ARCHIVE_PROTOCOL_V1,
        ]
        .into_iter()
        .collect();
        assert_eq!(ids.len(), 4);
    }

    #[test]
    fn capability_ids_use_version_1_minor() {
        // Low half of every "V1" ID is 0x0001 — matches Go's
        // ProtocolVersionV1 minor version byte layout.
        for id in [
            capabilities::GLOBAL_PROTOCOL_V1,
            capabilities::COMPUTE_PROTOCOL_V1,
            capabilities::TOKEN_PROTOCOL_V1,
            capabilities::ARCHIVE_PROTOCOL_V1,
        ] {
            assert_eq!(id & 0xFFFF, 0x0001, "id 0x{:08x} has wrong minor", id);
        }
    }
}
