//! The STARK configuration: KoalaBear traces, a degree-8 extension for
//! challenges, FRI over Keccak-256 Merkle commitments and a Keccak-256
//! Fiat–Shamir transcript. Everything is hash-based (no pairings, no trusted
//! setup).
//!
//! Post-quantum target (decided 2026-10-22): about 100 bits against a
//! quantum prover, taking Grover's square root on every search over the
//! Fiat–Shamir transcript — grinding queries, proof-of-work, or a challenge
//! that lands in a bad set:
//! - FRI: blowup 4 and 96 queries, 2 conjectured bits each, plus 16 bits of
//!   query grinding: 208 classical bits, about 104 quantum;
//! - challenges in KoalaBear^8 (about 2^248): a bad out-of-domain or
//!   batching challenge has probability about trace length / 2^248, about
//!   2^-220 here, 2^-110 under Grover (the degree-4 field gave 2^-50);
//! - Keccak-256 commitments: 128-bit collision resistance classically, at
//!   least 85 bits against a quantum collision search.

use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::StarkConfig;

pub type Val = KoalaBear;
pub type Challenge = BinomialExtensionField<Val, 8>;
type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
pub type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, Compress, 2, 32>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Dft = Radix2DitParallel<Val>;
pub type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

/// Domain separator of every storage proof transcript.
const TRANSCRIPT: &[u8] = b"quil/storage-stark/v1";

/// FRI with blowup 4, 96 queries and 16 bits of query grinding (the module's
/// post-quantum target).
pub fn config() -> Config {
    let hash = ByteHash {};
    let val_mmcs = ValMmcs::new(FieldHash::new(hash), Compress::new(hash), 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let fri = FriParameters {
        log_blowup: 2,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 96,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 16,
        mmcs: challenge_mmcs,
    };
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri);
    Config::new(pcs, Challenger::from_hasher(TRANSCRIPT.to_vec(), hash))
}
