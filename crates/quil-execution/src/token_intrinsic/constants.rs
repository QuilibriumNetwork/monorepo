//! Token intrinsic constants. Port of
//! `node/execution/intrinsics/token/token_configuration.go` constants
//! and `token_intrinsic_transaction.go` frame constants.

use quil_crypto::poseidon::hash_bytes_to_32;

// =====================================================================
// Token behavior flags (bit field)
// =====================================================================

pub type TokenIntrinsicBehavior = u16;

pub const MINTABLE: TokenIntrinsicBehavior = 1 << 0;
pub const BURNABLE: TokenIntrinsicBehavior = 1 << 1;
pub const DIVISIBLE: TokenIntrinsicBehavior = 1 << 2;
pub const ACCEPTABLE: TokenIntrinsicBehavior = 1 << 3;
pub const EXPIRABLE: TokenIntrinsicBehavior = 1 << 4;
pub const TENDERABLE: TokenIntrinsicBehavior = 1 << 5;

/// QUIL token behavior: mintable, burnable, divisible, acceptable,
/// expirable, tenderable.
pub const QUIL_BEHAVIOR: TokenIntrinsicBehavior =
    MINTABLE | BURNABLE | DIVISIBLE | ACCEPTABLE | EXPIRABLE | TENDERABLE;

// =====================================================================
// Mint behavior
// =====================================================================

pub type TokenMintBehavior = u16;

pub const NO_MINT_BEHAVIOR: TokenMintBehavior = 0;
pub const MINT_WITH_PROOF: TokenMintBehavior = 1 << 0;
pub const MINT_WITH_AUTHORITY: TokenMintBehavior = 1 << 1;
pub const MINT_WITH_SIGNATURE: TokenMintBehavior = 1 << 2;
pub const MINT_WITH_PAYMENT: TokenMintBehavior = 1 << 3;

// =====================================================================
// Proof basis
// =====================================================================

pub type ProofBasisType = u16;

pub const NO_PROOF_BASIS: ProofBasisType = 0;
pub const PROOF_OF_MEANINGFUL_WORK: ProofBasisType = 1;
pub const VERKLE_MULTIPROOF_WITH_SIGNATURE: ProofBasisType = 2;

// =====================================================================
// Fee basis
// =====================================================================

pub type FeeBasisType = u16;

pub const NO_FEE_BASIS: FeeBasisType = 0;
pub const PER_UNIT: FeeBasisType = 1;

// =====================================================================
// Frame constants (from token_intrinsic_transaction.go)
// =====================================================================

/// Frame at which v2.1 token behavior cutover occurred.
pub const FRAME_2_1_CUTOVER: u64 = 244200;
/// Frame at which extended enrollment period ended.
pub const FRAME_2_1_EXTENDED_ENROLL_END: u64 = 255840;
/// Frame at which extended enrollment confirmations ended.
pub const FRAME_2_1_EXTENDED_ENROLL_CONFIRM_END: u64 = FRAME_2_1_EXTENDED_ENROLL_END + 6500;

// =====================================================================
// Domain addresses (Poseidon-derived)
// =====================================================================

/// `poseidon("q_token")` → TOKEN_BASE_DOMAIN. Computed at init time
/// in Go; we compute lazily and cache.
pub fn token_base_domain() -> [u8; 32] {
    hash_bytes_to_32(b"q_token").expect("poseidon hash of q_token")
}

/// `poseidon("q_token_current_supply")` with byte 0 set to 0xFF
/// (out-of-field-modulus sentinel to prevent Poseidon collision).
pub fn token_supply_address() -> [u8; 32] {
    let mut addr = hash_bytes_to_32(b"q_token_current_supply")
        .expect("poseidon hash of q_token_current_supply");
    addr[0] = 0xFF;
    addr
}

/// `poseidon("q_token_additional_references")` with byte 0 = 0xFF.
pub fn token_additional_references_address() -> [u8; 32] {
    let mut addr = hash_bytes_to_32(b"q_token_additional_references")
        .expect("poseidon hash of q_token_additional_references");
    addr[0] = 0xFF;
    addr
}

/// QUIL token units: 8_000_000_000 (8 billion sub-units per QUIL).
pub const QUIL_TOKEN_UNITS: u64 = 8_000_000_000;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domains;

    #[test]
    fn behavior_flags_are_distinct_powers_of_two() {
        assert_eq!(MINTABLE, 1);
        assert_eq!(BURNABLE, 2);
        assert_eq!(DIVISIBLE, 4);
        assert_eq!(ACCEPTABLE, 8);
        assert_eq!(EXPIRABLE, 16);
        assert_eq!(TENDERABLE, 32);
    }

    #[test]
    fn quil_behavior_is_all_six_flags() {
        assert_eq!(QUIL_BEHAVIOR, 0x3F); // 0b111111
    }

    #[test]
    fn mint_behaviors_are_distinct() {
        assert_ne!(MINT_WITH_PROOF, MINT_WITH_AUTHORITY);
        assert_ne!(MINT_WITH_PROOF, MINT_WITH_SIGNATURE);
        assert_ne!(MINT_WITH_PROOF, MINT_WITH_PAYMENT);
    }

    #[test]
    fn token_base_domain_is_deterministic() {
        assert_eq!(token_base_domain(), token_base_domain());
        assert_ne!(token_base_domain(), [0u8; 32]);
    }

    #[test]
    fn token_supply_address_has_ff_prefix() {
        let addr = token_supply_address();
        assert_eq!(addr[0], 0xFF);
    }

    #[test]
    fn token_additional_references_address_has_ff_prefix() {
        let addr = token_additional_references_address();
        assert_eq!(addr[0], 0xFF);
    }

    #[test]
    fn quil_token_address_matches_domains_constant() {
        // The QUIL_TOKEN domain address in crate::domains should
        // equal poseidon("q_mainnet_token").
        let expected = hash_bytes_to_32(b"q_mainnet_token").unwrap();
        assert_eq!(expected, domains::QUIL_TOKEN);
    }

    #[test]
    fn frame_constants_are_ordered() {
        assert!(FRAME_2_1_CUTOVER < FRAME_2_1_EXTENDED_ENROLL_END);
        assert!(FRAME_2_1_EXTENDED_ENROLL_END < FRAME_2_1_EXTENDED_ENROLL_CONFIRM_END);
    }

    #[test]
    fn frame_2_1_confirm_end_matches_go() {
        assert_eq!(FRAME_2_1_EXTENDED_ENROLL_CONFIRM_END, 255840 + 6500);
    }
}
