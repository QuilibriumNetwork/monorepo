//! Raw ABI for the pinned native reference backend.
//!
//! # Safety
//! All calls require exclusive process-wide access to native commitment-key
//! state. Contexts own allocations and must be freed exactly once. Pointers,
//! lengths and constraint handles must satisfy the native adapter contract;
//! every polynomial buffer contains 256 coefficients. Native code can abort on
//! assertions/allocation failure and does not guarantee secret erasure.
//! This module is not a safe network-verifier interface.

/// Hold this lock across the entire native context lifetime, including free.
#[cfg(feature = "native-backend")]
pub static NATIVE_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(feature = "native-backend")]
pub mod ffi {
    use std::ffi::{c_int, c_void};
    pub type GaussianSampler = unsafe extern "C" fn(*const u8, u64, u32, u32, *mut i32) -> c_int;
    pub type RejectionDecider = unsafe extern "C" fn(u32, i64, i64, *const u8, *const u8, i32, *const u8, i32) -> c_int;
    extern "C" {
        pub fn quil_set_private_gaussian_sampler(sampler: Option<GaussianSampler>);
        pub fn quil_set_rejection_decider(decider: Option<RejectionDecider>);
        pub fn quil_fixture_exact_rejection(seed: *const u8, nonce: u64, kind: u32, zv: i64, vv: i64, standard_deviation: f64, repetition: f64) -> c_int;
        pub fn quil_fixture_private_stream(seed: *const u8, nonce: u64, blocks: usize, out: *mut u8) -> c_int;
        pub fn quil_fixture_sample_prg(seed: *const u8, nonce: u64, count: usize, scale: u32, mode: u32, out: *mut i64) -> c_int;
        pub fn quil_fixture_private_rejection(seed: *const u8, nonce: u64, kind: u32, zv: i64, vv: i64, variance: f64, repetition: f64) -> c_int;
        pub fn quil_fixture_rejection_parts(value: f64, mode: u32, out: *mut u8, exponent: *mut i32, precision: *mut u32) -> c_int;
        pub fn quil_fixture_test_sampling_error(ctx: *mut c_void, stage: u32, bytes: *mut u8, capacity: usize, written: *mut usize) -> c_int;
        pub fn quil_fixture_test_gaussian_limits() -> c_int;
        pub fn quil_fixture_test_partial_proof_cleanup() -> c_int;
        pub fn quil_fixture_test_coefficient_pool() -> c_int;
        pub fn quil_fixture_test_shake_absorption() -> c_int;
        pub fn quil_fixture_test_parallel_zq() -> c_int;
        pub fn quil_fixture_test_deferred_challenges() -> c_int;
        pub fn quil_fixture_test_parallel_refresh() -> c_int;
        pub fn quil_fixture_test_public_refresh() -> c_int;
        pub fn quil_fixture_test_wide_crt() -> c_int;
        pub fn quil_fixture_test_parallel_rotation() -> c_int;
        pub fn quil_fixture_test_parallel_jl() -> c_int;
        pub fn quil_fixture_ntt_benchmark(rounds: usize, seconds: *mut f64, digest: *mut u8) -> c_int;
        pub fn quil_fixture_test_signed_mulhi() -> c_int;
        pub fn quil_fixture_test_unsigned_mulhi() -> c_int;
        pub fn quil_fixture_test_poly_reduction() -> c_int;
        pub fn quil_fixture_test_poly_scale() -> c_int;
        pub fn quil_fixture_test_polz_center() -> c_int;
        pub fn quil_fixture_test_private_mask_range() -> c_int;
        pub fn quil_fixture_test_empty_optional_dachshund_parameters() -> c_int;
        pub fn quil_fixture_test_linear_only_rq_aggregation() -> c_int;
        pub fn quil_fixture_test_cached_offsets() -> c_int;
        pub fn quil_fixture_test_refresh_idempotent() -> c_int;
        pub fn quil_fixture_test_parallel_mul_add_refresh() -> c_int;
        pub fn quil_fixture_test_parallel_jl_mat() -> c_int;
        pub fn quil_fixture_test_parallel_ldr_zq() -> c_int;
        pub fn quil_fixture_new(count: usize, rings: usize, scalars: usize) -> *mut c_void;
        pub fn quil_fixture_new_public(count: usize, rings: usize, scalars: usize) -> *mut c_void;
        pub fn quil_fixture_new_typed(count: usize, rings: usize, scalars: usize, short_from: usize, short_normsq: *const u64, with_witness: c_int) -> *mut c_void;
        pub fn quil_fixture_short(ctx: *mut c_void, values: *const i64) -> c_int;
        pub fn quil_fixture_short_domain(ctx: *mut c_void) -> c_int;
        pub fn quil_fixture_binary(ctx: *mut c_void, values: *const i64) -> c_int;
        pub fn quil_fixture_binary_domain(ctx: *mut c_void) -> c_int;
        pub fn quil_fixture_linear(
            ctx: *mut c_void,
            count: usize,
            indices: *const usize,
            coefficients: *mut i64,
            rhs: *mut i64,
            full: c_int,
        ) -> c_int;
        pub fn quil_fixture_quadratic(
            ctx: *mut c_void,
            linear_count: usize,
            product_count: usize,
            linear: *const usize,
            left: *const usize,
            right: *const usize,
            products: *mut i64,
            coefficients: *mut i64,
            rhs: *mut i64,
        ) -> c_int;
        pub fn quil_fixture_check(ctx: *mut c_void) -> c_int;
        pub fn quil_fixture_check_count(ctx: *mut c_void) -> usize;
        pub fn quil_fixture_drop_witness(ctx: *mut c_void);
        pub fn quil_fixture_prove_encoded(
            ctx: *mut c_void,
            bytes: *mut u8,
            capacity: usize,
            written: *mut usize,
        ) -> c_int;
        pub fn quil_fixture_verify_encoded(
            ctx: *mut c_void,
            bytes: *const u8,
            size: usize,
        ) -> c_int;
        pub fn quil_fixture_free(ctx: *mut c_void);
    }
}

#[cfg(all(test, feature = "native-backend"))]
mod tests {
    #[test]
    fn parallel_scalar_aggregation_matches_serial_values_and_widths() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { crate::ffi::quil_fixture_test_parallel_zq() }, 1);
    }

    #[test]
    fn incremental_shake_matches_independent_absorption_across_boundaries() {
        assert_eq!(unsafe { crate::ffi::quil_fixture_test_shake_absorption() }, 1);
    }

    use super::ffi::*;
    #[test]
    fn deferred_challenges_preserve_interleaved_transcript_values_and_widths() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_deferred_challenges() }, 1);
    }
    #[test]
    fn parallel_projection_collapse_preserves_transcript_values_widths_and_inputs() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_parallel_jl() }, 1);
    }
    #[test]
    fn parallel_rotation_matches_serial_values_widths_and_preserves_inputs() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_parallel_rotation() }, 1);
    }
    #[test]
    fn unsigned_mulhi_matches_wide_integer_reference() {
        assert_eq!(unsafe { quil_fixture_test_unsigned_mulhi() }, 1);
    }
    #[test]
    fn wide_crt_matches_scalar_limb_reference_and_preserves_inputs() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_wide_crt() }, 1);
    }
    #[test]
    fn public_zero_refresh_matches_serial_and_preserves_sentinels() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_public_refresh() }, 1);
    }
    #[test]
    fn parallel_refresh_matches_serial_values_widths_and_untouched_slices() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_parallel_refresh() }, 1);
    }
    #[test]
    fn sliced_mul_add_refresh_matches_serial_with_and_without_overflow_refresh() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_parallel_mul_add_refresh() }, 1);
    }
    #[test]
    fn refresh_is_idempotent_on_canonical_values_and_widths() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_refresh_idempotent() }, 1);
    }
    #[test]
    fn batched_lnp_collapse_matches_serial_outputs_and_preserves_inputs() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_parallel_jl_mat() }, 1);
    }
    #[test]
    fn batched_normal_round_zq_aggregation_matches_serial_transcript_and_values() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_parallel_ldr_zq() }, 1);
    }
    #[test]
    fn empty_commitment_groups_preserve_linear_constraint_aggregation() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_linear_only_rq_aggregation() }, 1);
    }
    #[test]
    fn absent_optional_constraints_do_not_inherit_parameter_memory() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_empty_optional_dachshund_parameters() }, 1);
    }
    #[test]
    fn private_mask_decomposition_preserves_signed_values_and_checks_ranges() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_private_mask_range() }, 1);
    }
    #[test]
    fn sampling_error_partial_proofs_can_be_freed() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_partial_proof_cleanup() }, 1);
        assert_eq!(unsafe { quil_fixture_test_gaussian_limits() }, 1);
        for kind in 0..=2 {
            for (variance, repetition) in [(f64::INFINITY, 2.0), (8.0, f64::INFINITY), (8.0, 0.5)] {
                assert_eq!(unsafe { quil_fixture_private_rejection([3;32].as_ptr(), 0, kind, 0, 4, variance, repetition) }, -1);
            }
        }
    }
    #[test]
    fn common_coefficients_share_storage_without_changing_the_statement() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_coefficient_pool() }, 1);
    }

    #[test]
    #[ignore = "explicit transform microbenchmark on deterministic public inputs"]
    fn native_ntt_microbenchmark() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        let mut digest = [0u8; 32];
        let mut seconds = [0f64; 2];
        assert_eq!(unsafe { quil_fixture_ntt_benchmark(2048, seconds.as_mut_ptr(), digest.as_mut_ptr()) }, 1);
        let digest: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(digest, "7b3ea0657641c73f2c1dd16131a4a38b0a8bda5c4fe9527a21385fbc523248a8",
            "transform outputs differ from the pinned portable implementation");
        eprintln!("native_ntt_benchmark rounds_per_prime=2048 primes=6 forward_seconds={:.6} inverse_seconds={:.6} output_digest={digest}",seconds[0],seconds[1]);
    }

    #[test]
    fn coefficient_centering_matches_wrapping_integer_reference() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_polz_center() }, 1);
    }

    #[test]
    fn polynomial_scale_matches_integer_reference_with_aliasing() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_poly_scale() }, 1);
    }

    #[test]
    fn polynomial_reduction_matches_integer_reference_for_all_signed_inputs() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_poly_reduction() }, 1);
    }

    #[test]
    fn signed_multiply_high_matches_integer_reference_at_boundaries() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_signed_mulhi() }, 1);
    }
    #[test]
    fn cached_offsets_match_generic_statement_and_transcript() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { quil_fixture_test_cached_offsets() }, 1);
    }
    #[test]
    fn public_context_abi_has_no_assignment_and_rejects_invalid_framing() {
        let _guard = super::NATIVE_STATE.lock().unwrap();
        unsafe {
            let context = quil_fixture_new_public(1, 0, 0);
            assert!(!context.is_null());
            assert_eq!(quil_fixture_binary_domain(context), 0);
            assert_eq!(quil_fixture_binary_domain(context), 1);
            assert_eq!(quil_fixture_check(context), 0);
            assert_eq!(quil_fixture_check_count(context), 0);
            assert_eq!(
                quil_fixture_verify_encoded(context, [0u8; 40].as_ptr(), 40),
                0
            );
            quil_fixture_free(context);
        }
    }
}
