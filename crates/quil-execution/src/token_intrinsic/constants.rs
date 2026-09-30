//! Token intrinsic constants. Port of
//! `node/execution/intrinsics/token/token_configuration.go` constants
//! and `token_intrinsic_transaction.go` frame constants.

use quil_crypto::poseidon::hash_bytes_to_32;

/// Confidential token operation codes. Shared by current QCT3 routing and
/// historical codecs; the payload's version tag selects its encoding.
/// App-shard frames anchor to the global frame this many frames behind the
/// latest one the proposer holds (`app_engine::resolve_global_anchor`).
pub const GLOBAL_ANCHOR_SAFETY_MARGIN: u64 = 4;

/// A mint claim executes in an app-shard frame whose anchor is at least
/// `GLOBAL_ANCHOR_SAFETY_MARGIN` behind the latest global frame, and admits
/// only citations at or before that anchor. Claim witnesses cite a frame this
/// far behind the latest global frame, leaving slack for proposer lag.
pub const MINT_CLAIM_CITATION_LAG: u64 = 2 * GLOBAL_ANCHOR_SAFETY_MARGIN;

pub const TYPE_LATTICE_TRANSACTION: u32 = 0x0512;
pub const TYPE_LATTICE_MINT: u32 = 0x0513;
pub const TYPE_LATTICE_PENDING: u32 = 0x0514;
pub const TYPE_LATTICE_PENDING_CLAIM: u32 = 0x0515;
pub const TYPE_LATTICE_SHIELD: u32 = 0x0516;
/// Global-authorization consumption; unsupported by the old suite.
pub const TYPE_LATTICE_MINT_CLAIM: u32 = 0x0517;
/// Cross-domain QUIL settlement.
pub const TYPE_LATTICE_SETTLEMENT: u32 = 0x0518;
/// Delivery of a globally committed output into its owning shard's block.
/// Injected by the owning shard's proposer.
pub const TYPE_COIN_DELIVERY: u32 = 0x051A;

/// Historical accumulator root vertex, retained as a reserved address by
/// migration and current scans. Its value must survive removal of the old
/// accumulator implementation. It is distinct from `[0xff; 32]` metadata.
pub const LEGACY_ACCUMULATOR_ROOT_ADDRESS: [u8; 32] = {
    let mut address = [0xff; 32];
    address[31] = 0xfe;
    address
};

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
/// A proof-basis custom token commits to a Merkle root of mint entitlements
/// in its configuration (`TokenMintStrategy.verkle_root`), and each mint
/// proves its leaf. Replaces the verkle basis, whose KZG
/// commitments the post-quantum node no longer carries. Custom tokens never
/// mint by proof of meaningful work.
pub const MERKLE_ENTITLEMENT_WITH_SIGNATURE: ProofBasisType = 3;

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

/// Activation frame for global-level execution of UNCOVERED shards'
/// general transactions. At/after this frame, a shard whose active
/// prover count is `<= HALT_RISK_PROVER_COUNT` has its token/compute/
/// hypergraph transactions executed (and fees charged) at the global
/// level instead of being dropped, so a newly-created or coverage-lost
/// shard isn't a dead zone where only prover-lifecycle ops can be
/// processed. NEW protocol rule (no Go equivalent) — gated so all nodes
/// switch behavior at the same height. See the global frame materializer.
///
/// Set to the first CW-driven frame (the mainnet BLS/KZG→commonware flag day,
/// where 669975 is the last legacy frame), so uncovered-shard global routing is
/// live from the very first frame the new consensus produces.
pub const FRAME_2_1_GLOBAL_UNCOVERED_SHARD_TX: u64 = 669976;

/// The same rule on every network other than mainnet: test networks never
/// reach the mainnet flag-day height, so they route uncovered-shard
/// transactions and deploys through the global venue from their first frame.
pub const NON_MAINNET_GLOBAL_UNCOVERED_SHARD_TX: u64 = 1;

/// Fewest active provers with which an application shard produces its own
/// frames: 3 on mainnet (the halt-risk floor), 1 elsewhere.
pub fn min_active_provers_for_shard_frames(network: u8) -> u64 {
    if network == crate::pricing::MAINNET_NETWORK { 3 } else { 1 }
}

/// Whether the global venue executes an application's bundles: exactly when
/// its shard cannot produce frames. The two rules must be complements, or a
/// bundle delivered to both venues (anyone can republish it to the global
/// topic) executes twice against separate state.
pub fn shard_is_globally_executed(network: u8, active_provers: u64) -> bool {
    active_provers < min_active_provers_for_shard_frames(network)
}

/// First global frame of uncovered-shard global execution for `network` (the
/// pricing network selector; mainnet is `pricing::MAINNET_NETWORK`).
pub fn global_uncovered_shard_tx_frame(network: u8) -> u64 {
    if network == crate::pricing::MAINNET_NETWORK {
        FRAME_2_1_GLOBAL_UNCOVERED_SHARD_TX
    } else {
        NON_MAINNET_GLOBAL_UNCOVERED_SHARD_TX
    }
}

#[cfg(test)]
mod uncovered_shard_tx_tests {
    #[test]
    fn mainnet_keeps_the_flag_day_and_other_networks_activate_immediately() {
        assert_eq!(super::global_uncovered_shard_tx_frame(0), 669_976);
        assert_eq!(super::global_uncovered_shard_tx_frame(1), 1);
        assert_eq!(super::global_uncovered_shard_tx_frame(5), 1);
    }

    #[test]
    fn global_execution_is_the_complement_of_shard_frame_production() {
        for network in [0u8, 1, 7] {
            for active in 0..8u64 {
                let produces = active >= super::min_active_provers_for_shard_frames(network);
                assert_ne!(produces, super::shard_is_globally_executed(network, active));
            }
        }
        assert!(super::shard_is_globally_executed(0, 2) && !super::shard_is_globally_executed(0, 3));
        assert!(super::shard_is_globally_executed(1, 0) && !super::shard_is_globally_executed(1, 1));
    }
}

// =====================================================================
// Domain addresses (Poseidon-derived)
// =====================================================================

/// `TOKEN_PREFIX` — `b"q_token"` (Go `token_configuration.go:37`). Used
/// both to derive `TOKEN_BASE_DOMAIN` and as the prefix in a deployed
/// token's domain derivation (`poseidon(TOKEN_PREFIX ‖ config_commit)`).
pub const TOKEN_PREFIX: &[u8] = b"q_token";

/// `poseidon("q_token")` → TOKEN_BASE_DOMAIN. Computed at init time
/// in Go; we compute lazily and cache.
pub fn token_base_domain() -> [u8; 32] {
    hash_bytes_to_32(TOKEN_PREFIX).expect("poseidon hash of q_token")
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

/// Retired Decaf operation codes; these identify rejections, not supported codecs.
pub const TYPE_TRANSACTION: u32 = 0x0509;
pub const TYPE_PENDING_TRANSACTION: u32 = 0x050c;
pub const TYPE_MINT_TRANSACTION: u32 = 0x050f;
