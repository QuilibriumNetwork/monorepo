#![allow(non_snake_case)]
#[macro_use]
extern crate criterion;
use criterion::Criterion;

use rand;
use rand::Rng;

use bulletproofs::curve_adapter::Scalar;

use merlin::Transcript;

use bulletproofs::RangeProof;
use bulletproofs::{BulletproofGens, PedersenGens};

static AGGREGATION_SIZES: [usize; 6] = [1, 2, 4, 8, 16, 32];

fn generate_little_endian_number(bit_size: usize) -> [u8; 56] {
  use self::rand::Rng;

  // Ensure bit_size is a power of two.
  assert!(bit_size.is_power_of_two(), "bit_size must be a power of two");

  // Initialize the array with zeros.
  let mut bytes = [0u8; 56];
  let mut rng = rand::thread_rng();

  // Determine how many full bytes and extra bits are needed.
  let full_bytes = bit_size / 8;
  let rem_bits = bit_size % 8;

  // Fill in the full bytes with random data.
  for i in 0..full_bytes {
      bytes[i] = rng.gen();
  }

  // If there is a partial byte (i.e. remaining bits not filling a whole byte),
  // generate a random byte and mask off the bits above the required number.
  if rem_bits > 0 && full_bytes < 56 {
      let random_byte: u8 = rng.gen();
      // Mask to keep only the lower `rem_bits` bits.
      bytes[full_bytes] = random_byte & ((1 << rem_bits) - 1);
  }

  bytes
}

fn create_aggregated_rangeproof_helper(n: usize, c: &mut Criterion) {
    let label = format!("Aggregated {}-bit rangeproof creation", n);

    c.bench_function_over_inputs(
        &label,
        move |b, &&m| {
            let pc_gens = PedersenGens::default();
            let bp_gens = BulletproofGens::new(n, m);
            let mut rng = rand::thread_rng();

            let values: Vec<Scalar> = (0..m).map(|_| Scalar::from_bits(generate_little_endian_number(n))).collect();
            let blindings: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();

            b.iter(|| {
                // Each proof creation requires a clean transcript.
                let mut transcript = Transcript::new(b"AggregateRangeProofBenchmark");

                RangeProof::prove_multiple(
                    &bp_gens,
                    &pc_gens,
                    &mut transcript,
                    &values,
                    &blindings,
                    n,
                )
            })
        },
        &AGGREGATION_SIZES,
    );
}

fn create_aggregated_rangeproof_n_8(c: &mut Criterion) {
    create_aggregated_rangeproof_helper(8, c);
}

fn create_aggregated_rangeproof_n_16(c: &mut Criterion) {
    create_aggregated_rangeproof_helper(16, c);
}

fn create_aggregated_rangeproof_n_32(c: &mut Criterion) {
    create_aggregated_rangeproof_helper(32, c);
}

fn create_aggregated_rangeproof_n_64(c: &mut Criterion) {
    create_aggregated_rangeproof_helper(64, c);
}

fn verify_aggregated_rangeproof_helper(n: usize, c: &mut Criterion) {
    let label = format!("Aggregated {}-bit rangeproof verification", n);

    c.bench_function_over_inputs(
        &label,
        move |b, &&m| {
            let pc_gens = PedersenGens::default();
            let bp_gens = BulletproofGens::new(n, m);
            let mut rng = rand::thread_rng();

            let values: Vec<Scalar> = (0..m).map(|_| Scalar::from_bits(generate_little_endian_number(n))).collect();
            let blindings: Vec<Scalar> = (0..m).map(|_| Scalar::random(&mut rng)).collect();

            let mut transcript = Transcript::new(b"AggregateRangeProofBenchmark");
            let (proof, value_commitments) = RangeProof::prove_multiple(
                &bp_gens,
                &pc_gens,
                &mut transcript,
                &values,
                &blindings,
                n,
            )
            .unwrap();

            b.iter(|| {
                // Each proof creation requires a clean transcript.
                let mut transcript = Transcript::new(b"AggregateRangeProofBenchmark");

                proof.verify_multiple(&bp_gens, &pc_gens, &mut transcript, &value_commitments, n)
            });
        },
        &AGGREGATION_SIZES,
    );
}

fn verify_aggregated_rangeproof_n_8(c: &mut Criterion) {
    verify_aggregated_rangeproof_helper(8, c);
}

fn verify_aggregated_rangeproof_n_16(c: &mut Criterion) {
    verify_aggregated_rangeproof_helper(16, c);
}

fn verify_aggregated_rangeproof_n_32(c: &mut Criterion) {
    verify_aggregated_rangeproof_helper(32, c);
}

fn verify_aggregated_rangeproof_n_64(c: &mut Criterion) {
    verify_aggregated_rangeproof_helper(64, c);
}

criterion_group! {
    name = create_rp;
    config = Criterion::default().sample_size(10);
    targets =
    create_aggregated_rangeproof_n_8,
    create_aggregated_rangeproof_n_16,
    create_aggregated_rangeproof_n_32,
    create_aggregated_rangeproof_n_64,
}

criterion_group! {
    name = verify_rp;
    config = Criterion::default();
    targets =
    verify_aggregated_rangeproof_n_8,
    verify_aggregated_rangeproof_n_16,
    verify_aggregated_rangeproof_n_32,
    verify_aggregated_rangeproof_n_64,
}

criterion_main!(create_rp, verify_rp);
