//! Phase-3 A/B bench: JMT hash-commit vs the KZG branch-commit.
//!
//! Mirrors `quil-tries/benches/bench_tree.rs` at the same tree sizes (64 /
//! 512 / 4096 leaves, keys = SHA-256(i)) so the numbers are directly
//! comparable to the KZG baseline:
//!
//!   KZG (`quil-tries`):  64 → ~19.8 ms   512 → ~68 ms   4096 → ~577 ms
//!
//! Two cases:
//!   * `forest_full_build`   — commit an N-leaf tree from empty (the direct
//!     analog of the KZG `commit()` of an N-leaf tree).
//!   * `forest_incremental`  — the realistic per-frame cost: one changed leaf
//!     on top of an already-built N-leaf tree (KZG has no incremental path;
//!     it re-multiexps every dirty branch).
//!
//! Run: `cargo bench -p quil-forest --bench bench_forest`

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use jmt::storage::TreeWriter;
use jmt::{KeyHash, Sha256Jmt};
use quil_forest::MemTreeStore;
use sha2::{Digest, Sha256};

/// N `(KeyHash, Some(value))` leaves whose keys are SHA-256(i) so they spread
/// across the trie (matching the KZG bench's leaf distribution).
fn leaves(n: usize) -> Vec<(KeyHash, Option<Vec<u8>>)> {
    (0..n)
        .map(|i| {
            let key = Sha256::digest((i as u64).to_be_bytes());
            let value = Sha256::digest([&b"v"[..], &key[..]].concat()).to_vec();
            (KeyHash::with::<Sha256>(key), Some(value))
        })
        .collect()
}

fn build(store: &MemTreeStore, entries: Vec<(KeyHash, Option<Vec<u8>>)>, version: u64) {
    let tree = Sha256Jmt::new(store);
    let (_root, batch) = tree.put_value_set(entries, version).unwrap();
    store.write_node_batch(&batch.node_batch).unwrap();
}

fn bench_full_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("forest_full_build");
    for &n in &[64usize, 512, 4096] {
        let entries = leaves(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter_batched(
                MemTreeStore::default,
                |store| {
                    build(&store, entries.clone(), 0);
                    black_box(&store);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn bench_incremental(c: &mut Criterion) {
    let mut group = c.benchmark_group("forest_incremental_1leaf");
    for &n in &[64usize, 512, 4096] {
        let base = leaves(n);
        // The single new leaf applied at version 1.
        let key = Sha256::digest(((n as u64) + 1).to_be_bytes());
        let value = Sha256::digest([&b"w"[..], &key[..]].concat()).to_vec();
        let update = vec![(KeyHash::with::<Sha256>(key), Some(value))];
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter_batched(
                || {
                    let store = MemTreeStore::default();
                    build(&store, base.clone(), 0);
                    store
                },
                |store| {
                    build(&store, update.clone(), 1);
                    black_box(&store);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_full_build, bench_incremental);
criterion_main!(benches);
