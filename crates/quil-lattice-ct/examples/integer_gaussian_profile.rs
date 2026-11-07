//! Single-thread sampler throughput using public fixture entropy only.
//! This measures the integer sampler, not complete proof time or security.
use quil_lattice_ct::confidential::relation::backend::portable::{
    expansion::CounterExpander,
    gaussian_exact::{gaussian_i32, SamplingBudget},
};
use std::{hint::black_box, time::Instant};

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(
        args.len(),
        2,
        "usage: integer_gaussian_profile COUNT ROUNDS"
    );
    let count: usize = args[0].parse().expect("coefficient count");
    let rounds: usize = args[1].parse().expect("round count");
    assert!((256..=1 << 20).contains(&count));
    assert!((3..=31).contains(&rounds));
    for scale in [0, 4, 12, 20, 26] {
        let mut times = Vec::with_capacity(rounds);
        // One unmeasured warmup; each round uses a different public nonce.
        for round in 0..=rounds {
            let mut stream = CounterExpander::aes256(&[42; 32], round as u64);
            let start = Instant::now();
            let samples = gaussian_i32(
                &mut stream,
                count,
                scale,
                SamplingBudget {
                    max_steps: count * 4096,
                    max_random_bytes: count * 4096 + 512,
                    max_coefficients: 1 << 24,
                },
            )
            .expect("sampling within native callback budgets");
            black_box(&samples);
            // Include output clearing, as the native callback does.
            drop(samples);
            if round != 0 {
                times.push(start.elapsed().as_secs_f64());
            }
        }
        times.sort_by(f64::total_cmp);
        let median = times[rounds / 2];
        println!("integer_gaussian_profile scale={scale} count={count} rounds={rounds} min_seconds={:.6} median_seconds={median:.6} max_seconds={:.6} median_coefficients_per_second={:.0}",
            times[0], times[rounds - 1], count as f64 / median);
    }
}
