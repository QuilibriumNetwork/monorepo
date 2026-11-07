//! Repeated complete native shield proofs. The LNP stage's input-witness
//! norm check fails on some attempts (Labradoodle's amortized
//! witness has no rejection bound); before the retry it aborted the process.
#![cfg(feature = "native-proof")]
use quil_lattice_ct::confidential::{
    relation::{
        backend::native::{self, NativeBudget},
        membership::IDENTITY_BYTES,
    },
    shield::ShieldStatement,
    transfer::{parameter_context, Output, MEMO_BYTES},
    AmountOpening, CommitmentKey,
};
use std::time::Instant;

#[test]
#[ignore = "repeated complete native shield proofs; minutes of CPU"]
fn repeated_shield_proofs_retry_failed_witness_checks() {
    let runs: usize = std::env::var("QUIL_SHIELD_STRESS_PROOFS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(16);
    let (network, application) = ([21; 32], [22; 32]);
    let key = CommitmentKey::derive(&parameter_context(&network, &application));
    let amounts = [u128::MAX - 258, 256];
    let openings: Vec<_> = (0..2u8)
        .map(|i| AmountOpening::from_seed(&[41; 32], &[i; 32]))
        .collect();
    let statement = ShieldStatement {
        network,
        application,
        transparent_address: [24; 32],
        owner_public_key: [23; 57],
        amount: u128::MAX,
        fee: 2,
        outputs: (0..2)
            .map(|i| Output {
                commitment: key.commit(amounts[i], &openings[i]),
                owner: [i as u8; IDENTITY_BYTES],
                memo: [0; MEMO_BYTES],
            })
            .collect(),
    };
    let pairs: Vec<_> = amounts.iter().copied().zip(&openings).collect();
    let budget = NativeBudget {
        max_native_bytes: 1024 * 1024 * 1024,
    };
    for run in 1..=runs {
        let started = Instant::now();
        let relation = statement.private_relation(&pairs, 2).unwrap();
        let proof = native::prove(&relation, budget)
            .unwrap_or_else(|e| panic!("shield proof {run}/{runs}: {e:?}"));
        drop(relation);
        let public = statement.public_relation(2).unwrap();
        assert!(native::verify_owned(public, &proof, budget).unwrap());
        eprintln!(
            "native_shield_stress proof={run}/{runs} bytes={} seconds={:.3}",
            proof.len(),
            started.elapsed().as_secs_f64()
        );
    }
}
