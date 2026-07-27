//! Signature-primitive microbenchmarks — the Phase-0 profiling input for the
//! consensus-signature axis (is the sig scheme a cost center worth changing?).
//!
//! - **Falcon-512 (FN-DSA)** is the current consensus signature (post-Falcon
//!   cutover). `verify` runs per vote/timeout on the hot path; `sign` runs once
//!   per produced vote (and carries the floating-point Gaussian sampler).
//! - **Ed448** is the transport / peer-identity signature.
//!
//! Run: `cargo bench -p quil-crypto --bench bench_sig`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use quil_crypto::{ed448_verify, falcon_verify, Ed448Signer, FalconSigner};
use quil_types::crypto::Signer;

fn falcon(c: &mut Criterion) {
    let signer = FalconSigner::generate();
    // A representative consensus payload (vote over a frame header hash + rank).
    let msg = b"quilibrium-global-consensus-vote:frame-header-hash||rank||qc";
    let domain = b"global";
    let sig = signer.sign_with_domain(msg, domain).unwrap();
    let pk = signer.public_key().to_vec();
    assert!(falcon_verify(&pk, &sig, msg, domain));

    c.bench_function("falcon512_verify", |b| {
        b.iter(|| {
            black_box(falcon_verify(
                black_box(&pk),
                black_box(&sig),
                black_box(&msg[..]),
                black_box(&domain[..]),
            ))
        })
    });
    c.bench_function("falcon512_sign", |b| {
        b.iter(|| black_box(signer.sign_with_domain(black_box(&msg[..]), black_box(&domain[..])).unwrap()))
    });
}

fn ed448(c: &mut Criterion) {
    let priv_key = [0x42u8; 57];
    let pub_key = Ed448Signer::derive_public(&priv_key).unwrap();
    let signer = Ed448Signer::from_bytes(&priv_key, &pub_key).unwrap();
    let msg = b"quilibrium-transport-handshake-challenge";
    let sig = signer.sign(msg).unwrap();
    assert!(ed448_verify(&pub_key, msg, &sig));

    c.bench_function("ed448_verify", |b| {
        b.iter(|| {
            black_box(ed448_verify(
                black_box(&pub_key),
                black_box(&msg[..]),
                black_box(&sig),
            ))
        })
    });
    c.bench_function("ed448_sign", |b| {
        b.iter(|| black_box(signer.sign(black_box(&msg[..])).unwrap()))
    });
}

criterion_group!(benches, falcon, ed448);
criterion_main!(benches);
