//! Phase-0 profiling bench: the KZG branch-commit hot path.
//!
//! `VectorCommitmentTree::commit` walks the 64-branch trie and, for every
//! branch node, builds a 4096-byte polynomial (64 children × 64-byte
//! commitments) and runs `KzgInclusionProver::commit` — a BLS48-581 G1
//! multiexp — with no incremental update. This bench isolates that cost at
//! several tree sizes so the verkle-vs-hash-Merkle decision (Phase 3) rests
//! on real numbers, and so a hash-Merkle branch commit can be A/B'd against
//! it in isolation.
//!
//! Run: `FLINT_DIR=/…/flint QUILIBRIUM_SIGNATURE_CHECK=false \
//!       cargo bench -p quil-tries --bench bench_tree`

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use num_bigint::BigInt;
use quil_crypto::KzgInclusionProver;
use quil_tries::VectorCommitmentTree;
use sha2::{Digest, Sha256};

/// Build a tree with `n` distinct leaves whose keys are `SHA-256(i)` so they
/// spread across the 64-ary branches (forcing real branch splits, not one
/// long chain).
fn build_tree(n: usize) -> VectorCommitmentTree {
    let mut tree = VectorCommitmentTree::new();
    for i in 0..n {
        let key = Sha256::digest((i as u64).to_be_bytes());
        let value = Sha256::digest([&b"v"[..], &key[..]].concat());
        tree.insert(&key, &value, &[], &BigInt::from(1u32)).unwrap();
    }
    tree
}

fn bench_tree_commit(c: &mut Criterion) {
    // Load the KZG SRS once (idempotent).
    quil_crypto::init();
    let prover = KzgInclusionProver;

    let mut group = c.benchmark_group("tree_commit");
    // Bracket realistic shard-tree sizes: one full branch (64), a small
    // shard, up to a busy shard.
    for &n in &[64usize, 512, 4096] {
        let mut tree = build_tree(n);
        // Warm one commit so the first timed iter isn't paying allocation
        // one-offs (commit still recomputes every branch each call).
        let _ = tree.commit(&prover);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                black_box(tree.commit(&prover));
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_tree_commit);
criterion_main!(benches);
