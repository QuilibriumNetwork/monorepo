//! Controlled A/B/C of recursive Rayon, serial, and production scheduling.
//! Defaults use the real SHA prover used by per-vertex commitments. Set
//! QUIL_TRIE_BENCH_PROVER=kzg to include native KZG arithmetic instead.
//! Tree/pool construction, warm-up, and correctness checks are outside timing.
use std::hint::black_box;
use std::time::Instant;
use num_bigint::BigInt;
use quil_tries::{ShaInclusionProver, VectorCommitmentNode, VectorCommitmentTree};
use quil_types::crypto::InclusionProver;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

fn old_commit(node: &mut VectorCommitmentNode, prover: &dyn InclusionProver, parallel: bool) {
    match node {
        VectorCommitmentNode::Leaf(leaf) => { leaf.commit(true); }
        VectorCommitmentNode::Branch(branch) => {
            if parallel {
                // Exact former traversal: all 64 slots, recursively parallel.
                branch.children.par_iter_mut().for_each(|child| {
                    if let Some(child) = child { old_commit(child, prover, true); }
                });
            } else {
                for child in branch.children.iter_mut().flatten() {
                    old_commit(child, prover, false);
                }
            }
            let mut aggregate = BigInt::from(0u64);
            for child in branch.children.iter().flatten() { aggregate += child.size(); }
            branch.size = aggregate;
            branch.commit(prover, true);
        }
    }
}

fn run(mode: usize, tree: &mut VectorCommitmentTree, prover: &dyn InclusionProver) -> Vec<u8> {
    if mode == 2 { return tree.commit(prover); }
    match tree.root.as_mut() {
        None => vec![0; 64],
        Some(node) => { old_commit(node, prover, mode == 0); node.commitment().to_vec() }
    }
}

fn build_tree(n: usize, shape: &str) -> VectorCommitmentTree {
    let mut tree = VectorCommitmentTree::new();
    for i in 0..n {
        let key = if shape == "uniform" {
            Sha256::digest((i as u64).to_le_bytes()).to_vec()
        } else {
            assert_eq!(shape, "sparse");
            // Binary occupancy in a 64-way trie: two occupied child slots per
            // branch, many small branches. The key still has a fixed width.
            let mut key = vec![0; 32];
            for bit in 0..32 {
                let offset = bit * 6 + 5;
                key[offset / 8] |= (((i as u64 >> bit) & 1) as u8) << (7 - offset % 8);
            }
            key
        };
        tree.insert(&key, &[42; 32], &[], &BigInt::from(1)).unwrap();
    }
    tree
}

#[cfg(unix)]
fn cpu_seconds() -> (f64, f64) {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // getrusage initializes the supplied structure on success.
    assert_eq!(unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) }, 0);
    let usage = unsafe { usage.assume_init() };
    let seconds = |v: libc::timeval| v.tv_sec as f64 + v.tv_usec as f64 / 1_000_000.0;
    (seconds(usage.ru_utime), seconds(usage.ru_stime))
}
#[cfg(not(unix))]
fn cpu_seconds() -> (f64, f64) { (f64::NAN, f64::NAN) }

fn numbers(name: &str, default: &str) -> Vec<usize> {
    std::env::var(name).unwrap_or_else(|_| default.into()).split(',')
        .map(|v| v.parse::<usize>().expect("positive comma-separated integer")).collect()
}

fn main() {
    let threads = numbers("QUIL_TRIE_BENCH_THREADS", "1,8,32,72,256");
    let sizes = numbers("QUIL_TRIE_BENCH_SIZES", "8,64,512,4096");
    let iters = numbers("QUIL_TRIE_BENCH_ITERS", "5")[0];
    let repeats = numbers("QUIL_TRIE_BENCH_REPEATS", "3")[0];
    assert!(iters > 0 && repeats > 0 && threads.iter().all(|n| *n > 0));
    let shapes = std::env::var("QUIL_TRIE_BENCH_SHAPES").unwrap_or_else(|_| "uniform,sparse".into());
    let prover_name = std::env::var("QUIL_TRIE_BENCH_PROVER").unwrap_or_else(|_| "sha".into());
    let prover: Box<dyn InclusionProver> = match prover_name.as_str() {
        "sha" => Box::new(ShaInclusionProver),
        "kzg" => { quil_crypto::init(); Box::new(quil_crypto::KzgInclusionProver) }
        _ => panic!("prover must be sha or kzg"),
    };
    eprintln!("os={} arch={} available_parallelism={:?} prover={prover_name}",
        std::env::consts::OS, std::env::consts::ARCH, std::thread::available_parallelism());
    println!("threads,shape,leaves,mode,repeat,iters,wall_us_per_commit,user_us_per_commit,sys_us_per_commit");
    for count in threads {
        let pool = rayon::ThreadPoolBuilder::new().num_threads(count).build().unwrap();
        for shape in shapes.split(',') {
            for &n in &sizes {
                let original = build_tree(n, shape);
                let mut trees: Vec<_> = (0..3).map(|_| VectorCommitmentTree { root: original.root.clone() }).collect();
                pool.install(|| {
                    let roots: Vec<_> = trees.iter_mut().enumerate().map(|(mode, tree)| run(mode, tree, prover.as_ref())).collect();
                    assert!(roots.windows(2).all(|w| w[0] == w[1]));
                    let encodings: Vec<_> = trees.iter().map(|t| quil_tries::serialize_tree(t.root.as_ref()).unwrap()).collect();
                    assert!(encodings.windows(2).all(|w| w[0] == w[1]), "all node commitments and metadata must match");
                });
                for repeat in 0..repeats {
                    // Rotate mode order to reduce systematic warm-cache bias.
                    for step in 0..3 {
                        let mode = (step + repeat) % 3;
                        // Let workers settle after the previous sample; this
                        // delay is excluded from both wall and CPU measurements.
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        let cpu_start = cpu_seconds();
                        let start = Instant::now();
                        pool.install(|| {
                            for _ in 0..iters { black_box(run(mode, &mut trees[mode], prover.as_ref())); }
                        });
                        let elapsed = start.elapsed().as_secs_f64();
                        let cpu_end = cpu_seconds();
                        let scale = 1_000_000.0 / iters as f64;
                        println!("{count},{shape},{n},{},{repeat},{iters},{:.3},{:.3},{:.3}",
                            ["recursive", "serial", "bounded"][mode], elapsed * scale,
                            (cpu_end.0 - cpu_start.0) * scale, (cpu_end.1 - cpu_start.1) * scale);
                    }
                }
            }
        }
        // Rayon pool teardown is asynchronous; keep it outside the next pool's
        // measured work. A process per thread count gives stricter isolation.
        drop(pool);
    }
}
