use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;

fn criterion_benchmark(c: &mut Criterion) {
    bls48581::init();
    let mut bytes = vec![0u8; 65536];
    rand::thread_rng().fill(&mut bytes[..]);

    let mut group = c.benchmark_group("commit");
    group.sample_size(10);
    group.bench_function("commit 16", |b| {
        b.iter(|| black_box(bls48581::commit_raw(&bytes, 16)))
    });
    group.bench_function("commit 128", |b| {
        b.iter(|| black_box(bls48581::commit_raw(&bytes, 128)))
    });
    group.bench_function("commit 256", |b| {
        b.iter(|| black_box(bls48581::commit_raw(&bytes, 256)))
    });
    group.bench_function("commit 1024", |b| {
        b.iter(|| black_box(bls48581::commit_raw(&bytes, 1024)))
    });
    group.bench_function("commit 65536", |b| {
        b.iter(|| black_box(bls48581::commit_raw(&bytes, 65536)))
    });
    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
