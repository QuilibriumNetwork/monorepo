//! Poseidon2-24 over KoalaBear as AIR columns: the permutation
//! [`quil_crypto::storage_hash`] computes natively, one permutation per row.
//!
//! The round constraints follow `p3-poseidon2-air` (MIT / Apache-2.0), whose
//! evaluator is private to that crate; here they evaluate a slice of a wider
//! row, so the permutation table can carry its bus multiplicity beside it.

use core::borrow::{Borrow, BorrowMut};
use core::mem::MaybeUninit;

use p3_air::AirBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::{
    GenericPoseidon2LinearLayersKoalaBear, KOALABEAR_POSEIDON2_RC_24_EXTERNAL_FINAL,
    KOALABEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL, KOALABEAR_POSEIDON2_RC_24_INTERNAL,
};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{generate_trace_rows_for_perm, num_cols, FullRound, PartialRound, Poseidon2Cols, RoundConstants};

use crate::config::Val;

pub const WIDTH: usize = 24;
const SBOX_DEGREE: u64 = 3;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 23;

pub type Cols<T> = Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;
type Layers = GenericPoseidon2LinearLayersKoalaBear;

/// Columns of one permutation.
pub const NUM_COLS: usize = num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();

fn round_constants() -> &'static RoundConstants<Val, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    static CONSTANTS: std::sync::OnceLock<RoundConstants<Val, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>> =
        std::sync::OnceLock::new();
    CONSTANTS.get_or_init(|| {
        RoundConstants::new(
            KOALABEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL,
            KOALABEAR_POSEIDON2_RC_24_INTERNAL,
            KOALABEAR_POSEIDON2_RC_24_EXTERNAL_FINAL,
        )
    })
}

/// Write the permutation of `input` into `row[..NUM_COLS]` and return its
/// output.
pub fn fill(row: &mut [Val], input: [Val; WIDTH]) -> [Val; WIDTH] {
    let row = &mut row[..NUM_COLS];
    // SAFETY: `MaybeUninit<Val>` has `Val`'s layout, and every slot is
    // already initialized.
    let uninit: &mut [MaybeUninit<Val>] =
        unsafe { core::slice::from_raw_parts_mut(row.as_mut_ptr().cast(), row.len()) };
    let cols: &mut Cols<MaybeUninit<Val>> = uninit.borrow_mut();
    generate_trace_rows_for_perm::<Val, Layers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(
        cols,
        input,
        round_constants(),
    );
    output(row)
}

/// The output a filled permutation slice holds.
pub fn output(row: &[Val]) -> [Val; WIDTH] {
    let cols: &Cols<Val> = row[..NUM_COLS].borrow();
    cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post
}

/// Constrain `cols` to one permutation; returns its input and output.
pub fn eval<AB: AirBuilder<F = Val>>(builder: &mut AB, cols: &Cols<AB::Var>) -> ([AB::Var; WIDTH], [AB::Var; WIDTH]) {
    let constants = PlainConstants::get();
    let mut state: [AB::Expr; WIDTH] = cols.inputs.map(Into::into);
    Layers::external_linear_layer(&mut state);
    for round in 0..HALF_FULL_ROUNDS {
        full_round(builder, &mut state, &cols.beginning_full_rounds[round], &constants.beginning[round]);
    }
    for round in 0..PARTIAL_ROUNDS {
        partial_round(builder, &mut state, &cols.partial_rounds[round], constants.partial[round]);
    }
    for round in 0..HALF_FULL_ROUNDS {
        full_round(builder, &mut state, &cols.ending_full_rounds[round], &constants.ending[round]);
    }
    (cols.inputs, cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post)
}

/// The round constants as plain arrays (the `RoundConstants` fields are
/// private to `p3-poseidon2-air`).
struct PlainConstants {
    beginning: [[Val; WIDTH]; HALF_FULL_ROUNDS],
    partial: [Val; PARTIAL_ROUNDS],
    ending: [[Val; WIDTH]; HALF_FULL_ROUNDS],
}

impl PlainConstants {
    fn get() -> &'static Self {
        static CONSTANTS: std::sync::OnceLock<PlainConstants> = std::sync::OnceLock::new();
        CONSTANTS.get_or_init(|| PlainConstants {
            beginning: KOALABEAR_POSEIDON2_RC_24_EXTERNAL_INITIAL,
            partial: KOALABEAR_POSEIDON2_RC_24_INTERNAL,
            ending: KOALABEAR_POSEIDON2_RC_24_EXTERNAL_FINAL,
        })
    }
}

fn full_round<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    state: &mut [AB::Expr; WIDTH],
    round: &FullRound<AB::Var, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    constants: &[Val; WIDTH],
) {
    for (s, &c) in state.iter_mut().zip(constants) {
        *s += c;
        *s = s.cube();
    }
    Layers::external_linear_layer(state);
    for (s, &post) in state.iter_mut().zip(round.post.iter()) {
        builder.assert_eq(s.clone(), post);
        *s = post.into();
    }
}

fn partial_round<AB: AirBuilder<F = Val>>(
    builder: &mut AB,
    state: &mut [AB::Expr; WIDTH],
    round: &PartialRound<AB::Var, SBOX_DEGREE, SBOX_REGISTERS>,
    constant: Val,
) {
    state[0] += constant;
    let cubed = state[0].cube();
    builder.assert_eq(cubed, round.post_sbox);
    state[0] = round.post_sbox.into();
    Layers::internal_linear_layer(state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_crypto::storage_hash as hash;

    #[test]
    fn the_columns_compute_the_native_permutation() {
        let mut row = vec![Val::ZERO; NUM_COLS];
        for seed in 0u32..4 {
            let input: [Val; WIDTH] = core::array::from_fn(|i| hash::felt(seed * 1000 + i as u32 * 7 + 1));
            let mut native = input;
            hash::permute(&mut native);
            assert_eq!(fill(&mut row, input), native);
        }
    }
}
