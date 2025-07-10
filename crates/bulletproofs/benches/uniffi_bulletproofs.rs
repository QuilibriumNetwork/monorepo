#[macro_use]
extern crate criterion;
use criterion::{black_box, Criterion};

use bulletproofs::uniffi_bulletproofs::*;
use rand::thread_rng;
use rand::Rng;

fn generate_random_scalar() -> Vec<u8> {
    let mut rng = thread_rng();
    let mut scalar = vec![0u8; 56];
    rng.fill(&mut scalar[..]);
    scalar
}

fn generate_random_scalars(count: usize) -> Vec<Vec<u8>> {
    (0..count).map(|_| generate_random_scalar()).collect()
}

fn benchmark_generate_input_commitments(c: &mut Criterion) {
    c.bench_function("generate_input_commitments_1", |b| {
        let values = generate_random_scalars(1);
        let blinding = generate_random_scalar();
        b.iter(|| {
            generate_input_commitments(
                black_box(values.clone()),
                black_box(blinding.clone()),
            )
        });
    });

    c.bench_function("generate_input_commitments_10", |b| {
        let values = generate_random_scalars(10);
        let blinding = generate_random_scalar();
        b.iter(|| {
            generate_input_commitments(
                black_box(values.clone()),
                black_box(blinding.clone()),
            )
        });
    });
}

fn benchmark_generate_range_proof(c: &mut Criterion) {
    c.bench_function("generate_range_proof_32bit_single", |b| {
        let values = generate_random_scalars(1);
        let blinding = generate_random_scalar();
        b.iter(|| {
            generate_range_proof(
                black_box(values.clone()),
                black_box(blinding.clone()),
                black_box(32),
            )
        });
    });

    c.bench_function("generate_range_proof_64bit_single", |b| {
        let values = generate_random_scalars(1);
        let blinding = generate_random_scalar();
        b.iter(|| {
            generate_range_proof(
                black_box(values.clone()),
                black_box(blinding.clone()),
                black_box(64),
            )
        });
    });

    c.bench_function("generate_range_proof_32bit_batch_4", |b| {
        let values = generate_random_scalars(4);
        let blinding = generate_random_scalar();
        b.iter(|| {
            generate_range_proof(
                black_box(values.clone()),
                black_box(blinding.clone()),
                black_box(32),
            )
        });
    });
}

fn benchmark_verify_range_proof(c: &mut Criterion) {
    // Generate proof once for verification benchmarks
    let values = generate_random_scalars(1);
    let blinding = generate_random_scalar();
    let proof_result = generate_range_proof(values, blinding, 32);
    
    c.bench_function("verify_range_proof_32bit", |b| {
        b.iter(|| {
            verify_range_proof(
                black_box(proof_result.proof.clone()),
                black_box(proof_result.commitment.clone()),
                black_box(32),
            )
        });
    });
}

fn benchmark_sum_check(c: &mut Criterion) {
    c.bench_function("sum_check_2_inputs_2_outputs", |b| {
        let input_commitments = vec![generate_random_scalar(), generate_random_scalar()];
        let output_commitments = vec![generate_random_scalar(), generate_random_scalar()];
        let additional_inputs = vec![];
        let additional_outputs = vec![];
        
        b.iter(|| {
            sum_check(
                black_box(input_commitments.clone()),
                black_box(additional_inputs.clone()),
                black_box(output_commitments.clone()),
                black_box(additional_outputs.clone()),
            )
        });
    });

    c.bench_function("sum_check_10_inputs_10_outputs", |b| {
        let input_commitments = generate_random_scalars(10);
        let output_commitments = generate_random_scalars(10);
        let additional_inputs = generate_random_scalars(5);
        let additional_outputs = generate_random_scalars(5);
        
        b.iter(|| {
            sum_check(
                black_box(input_commitments.clone()),
                black_box(additional_inputs.clone()),
                black_box(output_commitments.clone()),
                black_box(additional_outputs.clone()),
            )
        });
    });
}

fn benchmark_keygen(c: &mut Criterion) {
    c.bench_function("keygen", |b| {
        b.iter(|| {
            keygen()
        });
    });
}

fn benchmark_scalar_operations(c: &mut Criterion) {
    let scalar1 = generate_random_scalar();
    let scalar2 = generate_random_scalar();

    c.bench_function("scalar_mult", |b| {
        b.iter(|| {
            scalar_mult(
                black_box(scalar1.clone()),
                black_box(scalar2.clone()),
            )
        });
    });

    c.bench_function("scalar_addition", |b| {
        b.iter(|| {
            scalar_addition(
                black_box(scalar1.clone()),
                black_box(scalar2.clone()),
            )
        });
    });

    c.bench_function("scalar_subtraction", |b| {
        b.iter(|| {
            scalar_subtraction(
                black_box(scalar1.clone()),
                black_box(scalar2.clone()),
            )
        });
    });

    c.bench_function("scalar_inverse", |b| {
        b.iter(|| {
            scalar_inverse(black_box(scalar1.clone()))
        });
    });

    c.bench_function("scalar_to_point", |b| {
        b.iter(|| {
            scalar_to_point(black_box(scalar1.clone()))
        });
    });
}

fn benchmark_point_operations(c: &mut Criterion) {
    let scalar = generate_random_scalar();
    let point1 = scalar_to_point(generate_random_scalar());
    let point2 = scalar_to_point(generate_random_scalar());

    c.bench_function("scalar_mult_point", |b| {
        b.iter(|| {
            scalar_mult_point(
                black_box(scalar.clone()),
                black_box(point1.clone()),
            )
        });
    });

    c.bench_function("point_addition", |b| {
        b.iter(|| {
            point_addition(
                black_box(point1.clone()),
                black_box(point2.clone()),
            )
        });
    });

    c.bench_function("point_subtraction", |b| {
        b.iter(|| {
            point_subtraction(
                black_box(point1.clone()),
                black_box(point2.clone()),
            )
        });
    });
}

fn benchmark_hash_operations(c: &mut Criterion) {
    let scalar = generate_random_scalar();
    let point = scalar_to_point(generate_random_scalar());
    let input_data = vec![1u8; 64];

    c.bench_function("scalar_mult_hash_to_scalar", |b| {
        b.iter(|| {
            scalar_mult_hash_to_scalar(
                black_box(scalar.clone()),
                black_box(point.clone()),
            )
        });
    });

    c.bench_function("hash_to_scalar", |b| {
        b.iter(|| {
            hash_to_scalar(black_box(input_data.clone()))
        });
    });
}

fn benchmark_schnorr_simple(c: &mut Criterion) {
    let secret = generate_random_scalar();
    let message = vec![1u8; 32];
    let keypair = keygen();
    let public_key = keypair[56..].to_vec();
    
    c.bench_function("sign_simple", |b| {
        b.iter(|| {
            sign_simple(
                black_box(secret.clone()),
                black_box(message.clone()),
            )
        });
    });

    let signature = sign_simple(secret, message.clone());
    
    c.bench_function("verify_simple", |b| {
        b.iter(|| {
            verify_simple(
                black_box(message.clone()),
                black_box(signature.clone()),
                black_box(public_key.clone()),
            )
        });
    });
}

fn benchmark_schnorr_hidden(c: &mut Criterion) {
    let x = generate_random_scalar();
    let t = generate_random_scalar();
    let a = generate_random_scalar();
    let r = generate_random_scalar();

    c.bench_function("sign_hidden", |b| {
        b.iter(|| {
            sign_hidden(
                black_box(x.clone()),
                black_box(t.clone()),
                black_box(a.clone()),
                black_box(r.clone()),
            )
        });
    });

    let signature = sign_hidden(x, t.clone(), a, r);
    // Extract components from signature
    let c_bytes = signature[0..56].to_vec();
    let s1 = signature[56..112].to_vec();
    let s2 = signature[112..168].to_vec();
    let s3 = signature[168..224].to_vec();
    let p_point = signature[224..280].to_vec();
    let c_point = signature[280..336].to_vec();

    c.bench_function("verify_hidden", |b| {
        b.iter(|| {
            verify_hidden(
                black_box(c_bytes.clone()),
                black_box(t.clone()),
                black_box(s1.clone()),
                black_box(s2.clone()),
                black_box(s3.clone()),
                black_box(p_point.clone()),
                black_box(c_point.clone()),
            )
        });
    });
}

fn benchmark_alt_generator(c: &mut Criterion) {
    c.bench_function("alt_generator", |b| {
        b.iter(|| {
            alt_generator()
        });
    });
}

criterion_group!(
    benches,
    benchmark_generate_input_commitments,
    benchmark_generate_range_proof,
    benchmark_verify_range_proof,
    benchmark_sum_check,
    benchmark_keygen,
    benchmark_scalar_operations,
    benchmark_point_operations,
    benchmark_hash_operations,
    benchmark_schnorr_simple,
    benchmark_schnorr_hidden,
    benchmark_alt_generator
);

criterion_main!(benches);