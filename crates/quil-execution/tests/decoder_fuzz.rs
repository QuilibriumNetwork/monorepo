//! Property-based fuzz tests for canonical-bytes decoders.
//!
//! Two test families per type:
//!   1. **Roundtrip**: random struct → encode → decode → assert equal.
//!      Catches asymmetric encoder/decoder bugs.
//!   2. **Decode-fuzz**: random bytes → decode → must not panic.
//!      Catches allocate-before-bounds-check DoS and missing length
//!      checks.
//!
//! These run as part of `cargo test`; proptest defaults to 256 cases
//! per test. Override with `PROPTEST_CASES=10000` for a deeper run.

use proptest::prelude::*;

use quil_execution::global_intrinsic::{
    frame_header::{FrameHeader, GlobalFrameHeader},
    prover_join::ProverJoin,
    prover_ops::{ProverConfirm, ProverReject, ProverSeniorityMerge, ShardMerge, ShardSplit},
    AddressedSignature, ProverLeave, ProverPause, ProverResume, SignatureWithPop,
};
use quil_execution::hypergraph_intrinsic::{
    HyperedgeAdd, HyperedgeRemove, HypergraphConfiguration, HypergraphDeploy, HypergraphUpdate,
    VertexAdd, VertexRemove,
};
use quil_execution::hypergraph_intrinsic::canonical::AggregateSignature;
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use quil_execution::token_intrinsic::{
    MintTransaction, PendingTransaction, Transaction, TransactionInput, TransactionOutput,
};

// ---------------------------------------------------------------------
// Strategy helpers
// ---------------------------------------------------------------------

/// Bounded byte vector. The upper bound keeps proptest cases fast and
/// avoids spending all the time on huge inputs that exercise the same
/// codepath.
fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=max)
}

/// Fixed-length byte array generator.
fn bytes_fixed(len: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), len..=len)
}

fn addressed_sig() -> impl Strategy<Value = AddressedSignature> {
    (bytes_fixed(74), bytes_fixed(32)).prop_map(|(signature, address)| AddressedSignature {
        signature,
        address,
    })
}

fn sig_with_pop() -> impl Strategy<Value = SignatureWithPop> {
    (
        bytes_fixed(74),
        prop::option::of(bytes_fixed(585)),
        bytes_fixed(74),
    )
        .prop_map(|(signature, public_key, pop_signature)| SignatureWithPop {
            signature,
            public_key,
            pop_signature,
        })
}

fn aggregate_sig() -> impl Strategy<Value = AggregateSignature> {
    // signature: 74 (single signer) or 78 + N*516 for N in 1..=4
    let sig_strategy = prop_oneof![
        Just(74usize),
        Just(78 + 516),
        Just(78 + 516 * 2),
        Just(78 + 516 * 3),
    ]
    .prop_flat_map(|n| bytes_fixed(n));
    (
        sig_strategy,
        prop::option::of(bytes_fixed(585).prop_map(|kv| {
            quil_execution::hypergraph_intrinsic::canonical::Bls48581G2PublicKey {
                key_value: kv,
            }
        })),
        bytes(32),
    )
        .prop_map(|(signature, public_key, bitmask)| AggregateSignature {
            signature,
            public_key,
            bitmask,
        })
}

fn hypergraph_config() -> impl Strategy<Value = HypergraphConfiguration> {
    (
        bytes_fixed(57),
        bytes_fixed(57),
        prop_oneof![Just(Vec::<u8>::new()), bytes_fixed(585)],
    )
        .prop_map(
            |(read_public_key, write_public_key, owner_public_key)| HypergraphConfiguration {
                read_public_key,
                write_public_key,
                owner_public_key,
            },
        )
}

// ---------------------------------------------------------------------
// Roundtrip macro: encode → decode → assert equal
// ---------------------------------------------------------------------

macro_rules! roundtrip_test {
    ($name:ident, $ty:ty, $strat:expr) => {
        proptest! {
            #[test]
            fn $name(value in $strat) {
                let encoded: Vec<u8> = match value.to_canonical_bytes() {
                    Ok(b) => b,
                    // Encoder rejects this value (e.g., validation
                    // failure); skip — roundtrip undefined.
                    Err(_) => return Ok(()),
                };
                let decoded = <$ty>::from_canonical_bytes(&encoded)
                    .expect("decode of self-produced bytes must succeed");
                prop_assert_eq!(value, decoded);
            }
        }
    };
}

// ---------------------------------------------------------------------
// Decode-fuzz macro: random bytes → decode → no panic, bounded time
// ---------------------------------------------------------------------

macro_rules! decode_fuzz_test {
    ($name:ident, $ty:ty) => {
        proptest! {
            #[test]
            fn $name(data in bytes(64 * 1024)) {
                // The decoder must EITHER return Ok or Err; it must
                // never panic. proptest will minimize a panicking
                // input to the smallest reproducer.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let _ = <$ty>::from_canonical_bytes(&data);
                })).expect("decoder must not panic on arbitrary bytes");
            }
        }
    };
}

// =====================================================================
// Hypergraph intrinsic
// =====================================================================

roundtrip_test!(
    vertex_add_roundtrip,
    VertexAdd,
    (bytes_fixed(32), bytes_fixed(32), bytes(2048), bytes_fixed(114))
        .prop_map(|(domain, data_address, data, signature)| VertexAdd {
            domain,
            data_address,
            data,
            signature,
        })
);
decode_fuzz_test!(vertex_add_decode_fuzz, VertexAdd);

roundtrip_test!(
    vertex_remove_roundtrip,
    VertexRemove,
    (bytes_fixed(32), bytes_fixed(32), bytes_fixed(114))
        .prop_map(|(domain, data_address, signature)| VertexRemove {
            domain,
            data_address,
            signature,
        })
);
decode_fuzz_test!(vertex_remove_decode_fuzz, VertexRemove);

roundtrip_test!(
    hyperedge_add_roundtrip,
    HyperedgeAdd,
    (
        bytes_fixed(32),
        // Hyperedge value: [atom_type_byte][app_addr 32][data_addr 32][tail]
        (Just(0x01u8), bytes_fixed(32), bytes_fixed(32), bytes(256)).prop_map(
            |(t, app, data, tail)| {
                let mut v = Vec::with_capacity(1 + 32 + 32 + tail.len());
                v.push(t);
                v.extend_from_slice(&app);
                v.extend_from_slice(&data);
                v.extend_from_slice(&tail);
                v
            }
        ),
        bytes_fixed(114),
    )
        .prop_map(|(domain, value, signature)| HyperedgeAdd {
            domain,
            value,
            signature,
        })
);
decode_fuzz_test!(hyperedge_add_decode_fuzz, HyperedgeAdd);

roundtrip_test!(
    hyperedge_remove_roundtrip,
    HyperedgeRemove,
    (
        bytes_fixed(32),
        (Just(0x01u8), bytes_fixed(32), bytes_fixed(32)).prop_map(|(t, app, data)| {
            let mut v = Vec::with_capacity(1 + 64);
            v.push(t);
            v.extend_from_slice(&app);
            v.extend_from_slice(&data);
            v
        }),
        bytes_fixed(114),
    )
        .prop_map(|(domain, value, signature)| HyperedgeRemove {
            domain,
            value,
            signature,
        })
);
decode_fuzz_test!(hyperedge_remove_decode_fuzz, HyperedgeRemove);

roundtrip_test!(
    hypergraph_deploy_roundtrip,
    HypergraphDeploy,
    (hypergraph_config(), bytes(1024)).prop_map(|(config, rdf_schema)| HypergraphDeploy {
        config: Some(config),
        rdf_schema,
    })
);
decode_fuzz_test!(hypergraph_deploy_decode_fuzz, HypergraphDeploy);

roundtrip_test!(
    hypergraph_update_roundtrip,
    HypergraphUpdate,
    (
        prop::option::of(hypergraph_config()),
        bytes(1024),
        prop::option::of(aggregate_sig()),
    )
        .prop_map(
            |(config, rdf_schema, sig)| HypergraphUpdate {
                config,
                rdf_schema,
                public_key_signature_bls48581: sig,
            }
        )
);
decode_fuzz_test!(hypergraph_update_decode_fuzz, HypergraphUpdate);

// =====================================================================
// Message envelope (network-facing — highest-value attack surface)
// =====================================================================

decode_fuzz_test!(message_bundle_decode_fuzz, CanonicalMessageBundle);
decode_fuzz_test!(message_request_decode_fuzz, CanonicalMessageRequest);

// =====================================================================
// Global intrinsic
// =====================================================================

roundtrip_test!(
    prover_join_roundtrip,
    ProverJoin,
    (
        prop::collection::vec(bytes(64), 0..=4),
        any::<u64>(),
        prop::option::of(sig_with_pop()),
        // delegate_address: max 32 bytes per protocol
        bytes(32),
        Just(Vec::new()), // merge_targets — keeping simple
        bytes(2048),
    )
        .prop_map(
            |(filters, frame_number, sig, delegate_address, merge_targets, proof)| ProverJoin {
                filters,
                frame_number,
                public_key_signature_bls48581: sig,
                delegate_address,
                merge_targets,
                proof,
            }
        )
);
decode_fuzz_test!(prover_join_decode_fuzz, ProverJoin);

roundtrip_test!(
    prover_pause_roundtrip,
    ProverPause,
    (bytes_fixed(32), any::<u64>(), prop::option::of(addressed_sig())).prop_map(
        |(filter, frame_number, sig)| ProverPause {
            filter,
            frame_number,
            public_key_signature_bls48581: sig,
        }
    )
);
decode_fuzz_test!(prover_pause_decode_fuzz, ProverPause);

roundtrip_test!(
    prover_resume_roundtrip,
    ProverResume,
    (bytes_fixed(32), any::<u64>(), prop::option::of(addressed_sig())).prop_map(
        |(filter, frame_number, sig)| ProverResume {
            filter,
            frame_number,
            public_key_signature_bls48581: sig,
        }
    )
);
decode_fuzz_test!(prover_resume_decode_fuzz, ProverResume);

roundtrip_test!(
    prover_leave_roundtrip,
    ProverLeave,
    (
        prop::collection::vec(bytes_fixed(32), 0..=4),
        any::<u64>(),
        prop::option::of(addressed_sig()),
    )
        .prop_map(|(filters, frame_number, sig)| ProverLeave {
            filters,
            frame_number,
            public_key_signature_bls48581: sig,
        })
);
decode_fuzz_test!(prover_leave_decode_fuzz, ProverLeave);

// ProverConfirm's `filter` field is deprecated — the encoder always
// substitutes the literal `b"reserved"*4` marker regardless of the
// caller-supplied value, so roundtrip on arbitrary filter bytes is
// undefined by design. Pin filter to the marker so roundtrip exercises
// the rest of the struct.
roundtrip_test!(
    prover_confirm_roundtrip,
    ProverConfirm,
    (
        any::<u64>(),
        prop::option::of(addressed_sig()),
        prop::collection::vec(bytes_fixed(32), 0..=4),
    )
        .prop_map(|(frame_number, sig, filters)| ProverConfirm {
            filter: b"reservedreservedreservedreserved".to_vec(),
            frame_number,
            public_key_signature_bls48581: sig,
            filters,
        })
);
decode_fuzz_test!(prover_confirm_decode_fuzz, ProverConfirm);

// Same deprecated-filter substitution as ProverConfirm.
roundtrip_test!(
    prover_reject_roundtrip,
    ProverReject,
    (
        any::<u64>(),
        prop::option::of(addressed_sig()),
        prop::collection::vec(bytes_fixed(32), 0..=4),
    )
        .prop_map(|(frame_number, sig, filters)| ProverReject {
            filter: b"reservedreservedreservedreserved".to_vec(),
            frame_number,
            public_key_signature_bls48581: sig,
            filters,
        })
);
decode_fuzz_test!(prover_reject_decode_fuzz, ProverReject);

// ShardSplit roundtrip is hard to express with proptest (the proposed
// children must share the parent's prefix and have specific lengths).
// Skip the round-trip; the decode-fuzz path below catches panics.
decode_fuzz_test!(shard_split_decode_fuzz, ShardSplit);

decode_fuzz_test!(shard_merge_decode_fuzz, ShardMerge);
decode_fuzz_test!(prover_seniority_merge_decode_fuzz, ProverSeniorityMerge);

// =====================================================================
// Frame headers
// =====================================================================

decode_fuzz_test!(frame_header_decode_fuzz, FrameHeader);
decode_fuzz_test!(global_frame_header_decode_fuzz, GlobalFrameHeader);

// =====================================================================
// Token intrinsic
// =====================================================================

decode_fuzz_test!(transaction_decode_fuzz, Transaction);
decode_fuzz_test!(transaction_input_decode_fuzz, TransactionInput);
decode_fuzz_test!(transaction_output_decode_fuzz, TransactionOutput);
decode_fuzz_test!(mint_transaction_decode_fuzz, MintTransaction);
decode_fuzz_test!(pending_transaction_decode_fuzz, PendingTransaction);
