//! Rust ownership/submission boundary over the native backend.
//! Native assertions/allocation failures can abort, and native secret
//! erasure and constant-time behavior are not guaranteed.
use super::{submission::*, *};
use quil_lattice_proof_sys::{ffi, NATIVE_STATE};
use std::{collections::BTreeMap, ffi::c_void, ptr::NonNull, sync::MutexGuard};
use zeroize::Zeroizing;

pub const MAX_PROOF_BYTES: usize = 1 << 20;

#[derive(Debug, PartialEq, Eq)]
pub enum NativeError {
    InvalidRelation,
    AllocationBudget,
    NativeFailure(i32),
    Poisoned,
}

/// Prepare the native scalar row directly in its final flat buffer. Retain
/// zero/cancelled groups and original addition order: both affect the existing
/// boundary's transcript or checked-overflow behavior.
fn scalar_coefficients(row: &ScalarRow<'_>) -> Result<(Vec<usize>, Vec<i64>), NativeError> {
    if row.terms.is_empty() || row.terms.iter().any(|&(_, _, i)| i >= Poly::D) {
        return Err(NativeError::InvalidRelation);
    }
    let mut indices: Vec<_> = row.terms.iter().map(|&(_, p, _)| p).collect();
    indices.sort_unstable();
    indices.dedup();
    let length = indices.len().checked_mul(Poly::D).ok_or(NativeError::AllocationBudget)?;
    let mut coefficients = vec![0i64; length];
    let mut touched = Vec::with_capacity(row.terms.len());
    for &(a, p, i) in row.terms {
        let group = indices.binary_search(&p).expect("collected scalar handle");
        let position = group * Poly::D + if i == 0 { 0 } else { Poly::D - i };
        coefficients[position] = coefficients[position].checked_add(a)
            .ok_or(NativeError::InvalidRelation)?;
        touched.push(position);
    }
    touched.sort_unstable();
    touched.dedup();
    for position in touched {
        let value = &mut coefficients[position];
        if position % Poly::D != 0 {
            *value = value.checked_neg().ok_or(NativeError::InvalidRelation)?;
        }
        *value = center_public_coefficient(add_public_coefficient(0, *value));
    }
    Ok((indices, coefficients))
}

/// Submission accounting charged as unshared storage. This is neither a
/// measured peak-RSS limit nor a cap on the native prover workspace.
#[derive(Clone, Copy)]
pub struct NativeBudget {
    pub max_native_bytes: usize,
}

/// Produce bounded proof bytes. A failed submission always drops its native
/// context; no partially built statement can escape this API.
pub fn prove(
    relation: &CompiledAmountRelation,
    budget: NativeBudget,
) -> Result<Vec<u8>, NativeError> {
    let mut context = Context::new(false, budget)?;
    relation
        .submit_private_relation(&mut context)
        .map_err(submission_error)?;
    let mut proof = vec![0u8; MAX_PROOF_BYTES];
    let mut written = 0;
    let status = unsafe {
        ffi::quil_fixture_prove_encoded(
            context.ready()?,
            proof.as_mut_ptr(),
            proof.len(),
            &mut written,
        )
    };
    if status != 0 {
        return Err(NativeError::NativeFailure(status));
    }
    if written == 0 || written >= MAX_PROOF_BYTES {
        return Err(NativeError::InvalidRelation);
    }
    proof.truncate(written);
    Ok(proof)
}

/// Full fixed-fixture diagnostic for numerical-error propagation. Each stage
/// supplies invalid private sampling parameters and requires an error before
/// encoding, then rechecks that the original statement/witness are unchanged.
/// This runs the expensive prover; use only with public diagnostic fixtures.
#[doc(hidden)]
pub fn check_sampling_failure(
    relation: &CompiledAmountRelation,
    budget: NativeBudget,
    stage: u32,
) -> Result<(), NativeError> {
    if !(1..=3).contains(&stage) { return Err(NativeError::InvalidRelation); }
    let mut context = Context::new(false, budget)?;
    relation.submit_private_relation(&mut context).map_err(submission_error)?;
    let mut output = [0xa5u8; 32];
    let mut written = usize::MAX;
    let pointer = context.ready()?;
    let status = unsafe { ffi::quil_fixture_test_sampling_error(pointer, stage, output.as_mut_ptr(), output.len(), &mut written) };
    if status != 7 { return Err(NativeError::NativeFailure(status)); }
    if written != 0 || output != [0xa5; 32] || unsafe { ffi::quil_fixture_check(pointer) } != 1 {
        return Err(NativeError::InvalidRelation);
    }
    Ok(())
}

/// Verify a statement independently reconstructed from public transaction
/// data. No original witness is allocated or supplied to native verification.
pub fn verify(
    statement: &PublicAmountRelation,
    proof: &[u8],
    budget: NativeBudget,
) -> Result<bool, NativeError> {
    if proof.len() < 40 || proof.len() >= MAX_PROOF_BYTES || &proof[..8] != b"QPF6\0\0\0\0" {
        return Ok(false);
    }
    let mut context = Context::new(true, budget)?;
    statement.submit(&mut context).map_err(submission_error)?;
    verify_context(context, proof)
}

/// Consume a one-use public compiler relation. Submission copies coefficients
/// into native-owned storage, so release the Rust representation before the
/// verifier allocates its workspace. This is not a hard process memory cap.
pub fn verify_owned(
    statement: PublicAmountRelation,
    proof: &[u8],
    budget: NativeBudget,
) -> Result<bool, NativeError> {
    if proof.len() < 40 || proof.len() >= MAX_PROOF_BYTES || &proof[..8] != b"QPF6\0\0\0\0" {
        return Ok(false);
    }
    let mut context = Context::new(true, budget)?;
    statement.submit(&mut context).map_err(submission_error)?;
    drop(statement);
    verify_context(context, proof)
}

fn verify_context(context: Context, proof: &[u8]) -> Result<bool, NativeError> {
    let valid =
        unsafe { ffi::quil_fixture_verify_encoded(context.ready()?, proof.as_ptr(), proof.len()) };
    if unsafe { ffi::quil_fixture_check_count(context.ready()?) } != 0 {
        return Err(NativeError::InvalidRelation);
    }
    Ok(valid == 1)
}

fn submission_error(error: SubmissionError<NativeError>) -> NativeError {
    match error {
        SubmissionError::Sink(e) => e,
        _ => NativeError::InvalidRelation,
    }
}

// Native callbacks never unwind through C. Raw arrays have fixed ABI lengths;
// C retains the backing buffers for the entire synchronous call.
unsafe extern "C" fn rejection_decider(
    kind: u32, zv: i64, vv: i64, draw: *const u8,
    standard_deviation: *const u8, standard_deviation_exponent: i32,
    repetition: *const u8, repetition_exponent: i32,
) -> i32 {
    use super::portable::rejection::{decide_256, RejectionError, RejectionKind, RejectionParameters};
    if draw.is_null() || standard_deviation.is_null() || repetition.is_null() { return -1; }
    let result = std::panic::catch_unwind(|| {
        let kind = match kind {
            0 => RejectionKind::Standard, 1 => RejectionKind::SignFiltered,
            2 => RejectionKind::Bimodal, _ => return Err(RejectionError::Parameter),
        };
        let draw = unsafe { &*draw.cast::<[u8; 32]>() };
        let standard_deviation = unsafe { *standard_deviation.cast::<[u8; 16]>() };
        let repetition = unsafe { *repetition.cast::<[u8; 16]>() };
        let parameters = RejectionParameters::from_standard_deviation_components(
            u128::from_le_bytes(standard_deviation), standard_deviation_exponent,
            u128::from_le_bytes(repetition), repetition_exponent,
        )?;
        decide_256(kind, zv, vv, draw, &parameters)
    });
    match result { Ok(Ok(rejected)) => i32::from(rejected), _ => -1 }
}

unsafe extern "C" fn gaussian_sampler(
    seed: *const u8, nonce: u64, scale: u32, count: u32, output: *mut i32,
) -> i32 {
    use super::portable::{expansion::CounterExpander, gaussian_exact::{gaussian_i32, SamplingBudget}};
    if seed.is_null() || (count != 0 && output.is_null()) || scale > 26 || count > 1 << 24 { return -1; }
    if count == 0 { return 0; }
    let count = count as usize;
    let Some(max_steps) = count.checked_mul(4096) else { return -1; };
    let Some(max_random_bytes) = count.checked_mul(4096).and_then(|x| x.checked_add(512)) else { return -1; };
    let result = std::panic::catch_unwind(|| {
        let seed = unsafe { &*seed.cast::<[u8; 32]>() };
        let mut stream = CounterExpander::aes256(seed, nonce);
        gaussian_i32(&mut stream, count, scale, SamplingBudget {
            max_steps, max_random_bytes, max_coefficients: 1 << 24,
        })
    });
    match result {
        Ok(Ok(values)) => {
            unsafe { std::ptr::copy_nonoverlapping(values.as_ptr(), output, count) };
            0
        }
        _ => -1,
    }
}

struct Context {
    pointer: Option<NonNull<c_void>>,
    // Released only after Drop frees the native context and its global key.
    _guard: MutexGuard<'static, ()>,
    public: bool,
    budget: usize,
    estimated: usize,
    expected: Option<SubmissionCounts>,
    next: usize,
    scalars: usize,
    lines: usize,
    selections: usize,
    finished: bool,
}

impl Drop for Context {
    fn drop(&mut self) {
        if let Some(pointer) = self.pointer.take() {
            unsafe { ffi::quil_fixture_free(pointer.as_ptr()) };
        }
        unsafe {
            ffi::quil_set_rejection_decider(None);
            ffi::quil_set_private_gaussian_sampler(None);
        }
    }
}

impl Context {
    fn new(public: bool, budget: NativeBudget) -> Result<Self, NativeError> {
        let guard = NATIVE_STATE.lock().map_err(|_| NativeError::Poisoned)?;
        unsafe {
            ffi::quil_set_rejection_decider(Some(rejection_decider));
            ffi::quil_set_private_gaussian_sampler(Some(gaussian_sampler));
        }
        Ok(Self {
            pointer: None,
            _guard: guard,
            public,
            budget: budget.max_native_bytes,
            estimated: 0,
            expected: None,
            next: 0,
            scalars: 0,
            lines: 0,
            selections: 0,
            finished: false,
        })
    }
    fn ptr(&self) -> Result<*mut c_void, NativeError> {
        self.pointer
            .map(NonNull::as_ptr)
            .ok_or(NativeError::InvalidRelation)
    }
    fn ready(&self) -> Result<*mut c_void, NativeError> {
        if !self.finished {
            return Err(NativeError::InvalidRelation);
        }
        self.ptr()
    }
    fn charge(&mut self, bytes: usize) -> Result<(), NativeError> {
        self.estimated = self
            .estimated
            .checked_add(bytes)
            .ok_or(NativeError::AllocationBudget)?;
        if self.estimated > self.budget {
            return Err(NativeError::AllocationBudget);
        }
        Ok(())
    }
    fn start(
        &mut self,
        modulus: i128,
        degree: usize,
        counts: SubmissionCounts,
        short_normsq: &[u64],
    ) -> Result<(), NativeError> {
        if self.expected.is_some() || modulus != PROOF_MODULUS || degree != Poly::D {
            return Err(NativeError::InvalidRelation);
        }
        let binary = counts
            .original_binary_polynomials
            .checked_add(counts.auxiliary_binary_polynomials)
            .ok_or(NativeError::AllocationBudget)?;
        let n = binary
            .checked_add(counts.short_polynomials)
            .ok_or(NativeError::AllocationBudget)?;
        let rings = counts
            .linear_equations
            .checked_add(counts.selection_equations)
            .ok_or(NativeError::AllocationBudget)?;
        if n == 0 || n > 500_000 || rings > 400_000 || counts.scalar_equations > 2_000_000
            || short_normsq.len() != counts.short_polynomials
        {
            return Err(NativeError::InvalidRelation);
        }
        self.charge(n * 1024 + (rings + counts.scalar_equations) * 512)?;
        let pointer = unsafe {
            if counts.short_polynomials > 0 {
                ffi::quil_fixture_new_typed(n, rings, counts.scalar_equations, binary, short_normsq.as_ptr(), if self.public { 0 } else { 1 })
            } else if self.public {
                ffi::quil_fixture_new_public(n, rings, counts.scalar_equations)
            } else {
                ffi::quil_fixture_new(n, rings, counts.scalar_equations)
            }
        };
        self.pointer = Some(NonNull::new(pointer).ok_or(NativeError::InvalidRelation)?);
        self.expected = Some(counts);
        Ok(())
    }
    /// Short witness at a global index at or beyond every binary polynomial.
    fn short_domain(&mut self, index: usize, values: Option<&[i64]>) -> Result<(), NativeError> {
        let expected = self.expected.ok_or(NativeError::InvalidRelation)?;
        let binary = expected.original_binary_polynomials + expected.auxiliary_binary_polynomials;
        if self.finished || index != self.next || index < binary || index >= binary + expected.short_polynomials {
            return Err(NativeError::InvalidRelation);
        }
        let status = match (self.public, values) {
            (true, None) => unsafe { ffi::quil_fixture_short_domain(self.ptr()?) },
            (false, Some(values)) if values.len() == Poly::D => {
                let coefficients = Zeroizing::new(std::array::from_fn::<_, 256, _>(|i| values[i]));
                unsafe { ffi::quil_fixture_short(self.ptr()?, coefficients.as_ptr()) }
            }
            _ => return Err(NativeError::InvalidRelation),
        };
        if status != 0 {
            return Err(NativeError::NativeFailure(status));
        }
        self.next += 1;
        Ok(())
    }
    fn domain(&mut self, index: usize, values: Option<&[u8]>) -> Result<(), NativeError> {
        let expected = self.expected.ok_or(NativeError::InvalidRelation)?;
        if self.finished
            || index != self.next
            || index >= expected.original_binary_polynomials + expected.auxiliary_binary_polynomials
        {
            return Err(NativeError::InvalidRelation);
        }
        let status = match (self.public, values) {
            (true, None) => unsafe { ffi::quil_fixture_binary_domain(self.ptr()?) },
            (false, Some(values)) if values.len() == Poly::D && values.iter().all(|&v| v <= 1) => {
                let coefficients =
                    Zeroizing::new(std::array::from_fn::<_, 256, _>(|i| i64::from(values[i])));
                unsafe { ffi::quil_fixture_binary(self.ptr()?, coefficients.as_ptr()) }
            }
            _ => return Err(NativeError::InvalidRelation),
        };
        if status != 0 {
            return Err(NativeError::NativeFailure(status));
        }
        self.next += 1;
        Ok(())
    }
    fn linear_row(
        &mut self,
        terms: &[(Vec<i64>, usize)],
        rhs: &[i64],
        full: bool,
    ) -> Result<(), NativeError> {
        self.linear_row_with_unique_handles(terms, rhs, full, false)
    }

    fn linear_row_with_unique_handles(
        &mut self,
        terms: &[(Vec<i64>, usize)],
        rhs: &[i64],
        full: bool,
        unique: bool,
    ) -> Result<(), NativeError> {
        let expected = self.expected.ok_or(NativeError::InvalidRelation)?;
        if self.finished
            || (unique && terms.windows(2).any(|pair| pair[0].1 >= pair[1].1))
            || terms.is_empty()
            || rhs.len() != Poly::D
            || terms
                .iter()
                .any(|(p, i)| p.len() != Poly::D || *i >= self.next)
            || if full {
                self.lines >= expected.linear_equations
            } else {
                self.scalars >= expected.scalar_equations
            }
        {
            return Err(NativeError::InvalidRelation);
        }
        // Scalar rows have already combined and sorted their handles. Reuse
        // those vectors; general ring rows still need modular grouping.
        let grouped_terms;
        let terms = if unique {
            terms
        } else {
            let mut grouped: BTreeMap<usize, Vec<i64>> = BTreeMap::new();
            for (polynomial, index) in terms {
                let target = grouped.entry(*index).or_insert_with(|| vec![0; Poly::D]);
                for (target, &value) in target.iter_mut().zip(polynomial) {
                    *target = add_public_coefficient(*target, value);
                }
            }
            grouped_terms = grouped.into_iter()
                .map(|(index, values)| (values, index)).collect::<Vec<_>>();
            &grouped_terms
        };
        self.charge(
            (terms.len() + 1)
                .checked_mul(4096)
                .ok_or(NativeError::AllocationBudget)?,
        )?;
        let indices: Vec<_> = terms.iter().map(|(_, i)| *i).collect();
        let mut coefficients: Vec<_> = terms
            .iter()
            .flat_map(|(p, _)| {
                p.iter().map(|&v| {
                    center_public_coefficient(if unique { add_public_coefficient(0, v) } else { v })
                })
            })
            .collect();
        let mut rhs = rhs.to_vec();
        let status = unsafe {
            ffi::quil_fixture_linear(
                self.ptr()?,
                terms.len(),
                indices.as_ptr(),
                coefficients.as_mut_ptr(),
                rhs.as_mut_ptr(),
                i32::from(full),
            )
        };
        if status != 0 {
            return Err(NativeError::NativeFailure(status));
        }
        if full {
            self.lines += 1;
        } else {
            self.scalars += 1;
        }
        Ok(())
    }
    fn scalar_row(&mut self, row: ScalarRow<'_>) -> Result<(), NativeError> {
        let expected = self.expected.ok_or(NativeError::InvalidRelation)?;
        if self.finished || self.scalars >= expected.scalar_equations
            || row.terms.iter().any(|&(_, p, _)| p >= self.next) {
            return Err(NativeError::InvalidRelation);
        }
        let (indices, mut coefficients) = scalar_coefficients(&row)?;
        self.charge((indices.len() + 1).checked_mul(4096).ok_or(NativeError::AllocationBudget)?)?;
        let mut rhs = [0; Poly::D];
        rhs[0] = row.rhs;
        let status = unsafe {
            ffi::quil_fixture_linear(self.ptr()?, indices.len(), indices.as_ptr(),
                coefficients.as_mut_ptr(), rhs.as_mut_ptr(), 0)
        };
        if status != 0 { return Err(NativeError::NativeFailure(status)); }
        self.scalars += 1;
        Ok(())
    }
    fn selection_row(&mut self, row: SelectionRow) -> Result<(), NativeError> {
        let expected = self.expected.ok_or(NativeError::InvalidRelation)?;
        if self.finished
            || self.selections >= expected.selection_equations
            || row.terms.is_empty()
            || row.terms.len() > 64
            || row.handles().any(|i| i >= self.next)
            || row.terms.iter().any(|&(w, ..)| w == 0 || w.abs() >= (1i64 << 40))
        {
            return Err(NativeError::InvalidRelation);
        }
        let k = row.terms.len();
        self.charge((4 * k + 1) * 4096)?;
        // Linear part: Σ w (zero − selected); quadratic part: Σ w·s·one − w·s·zero.
        let mut indices = Vec::with_capacity(2 * k);
        let mut left = Vec::with_capacity(2 * k);
        let mut right = Vec::with_capacity(2 * k);
        let mut products = Vec::with_capacity(2 * k);
        let mut coefficients = vec![0i64; 2 * k * Poly::D];
        for (n, &(w, zero, one, selected)) in row.terms.iter().enumerate() {
            indices.push(zero);
            indices.push(selected);
            coefficients[(2 * n) * Poly::D] = w;
            coefficients[(2 * n + 1) * Poly::D] = -w;
            left.push(row.selector);
            right.push(one);
            products.push(w);
            left.push(row.selector);
            right.push(zero);
            products.push(-w);
        }
        let mut rhs = vec![0; Poly::D];
        let status = unsafe {
            ffi::quil_fixture_quadratic(
                self.ptr()?,
                2 * k,
                2 * k,
                indices.as_ptr(),
                left.as_ptr(),
                right.as_ptr(),
                products.as_mut_ptr(),
                coefficients.as_mut_ptr(),
                rhs.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(NativeError::NativeFailure(status));
        }
        self.selections += 1;
        Ok(())
    }
    fn complete(&mut self, counts: SubmissionCounts) -> Result<(), NativeError> {
        if self.finished
            || self.expected != Some(counts)
            || self.next != counts.original_binary_polynomials + counts.auxiliary_binary_polynomials + counts.short_polynomials
            || self.scalars != counts.scalar_equations
            || self.lines != counts.linear_equations
            || self.selections != counts.selection_equations
        {
            return Err(NativeError::InvalidRelation);
        }
        self.finished = true;
        Ok(())
    }
}

// Public coefficients only. Both summands are reduced before addition, so
// the sum fits i64; canonical residues can be centered with one subtraction.
const NATIVE_MODULUS: i64 = PROOF_MODULUS as i64;
const _: () = assert!(PROOF_MODULUS > 0 && PROOF_MODULUS < i64::MAX as i128 / 2);

fn add_public_coefficient(residue: i64, value: i64) -> i64 {
    debug_assert!((0..NATIVE_MODULUS).contains(&residue));
    let value = if (0..NATIVE_MODULUS).contains(&value) {
        value
    } else {
        value.rem_euclid(NATIVE_MODULUS)
    };
    let sum = residue + value;
    if sum >= NATIVE_MODULUS { sum - NATIVE_MODULUS } else { sum }
}

fn center_public_coefficient(residue: i64) -> i64 {
    debug_assert!((0..NATIVE_MODULUS).contains(&residue));
    if residue > NATIVE_MODULUS / 2 { residue - NATIVE_MODULUS } else { residue }
}

impl RelationSink for Context {
    type Error = NativeError;
    fn begin(&mut self, p: i128, d: usize, c: SubmissionCounts, n: &[u64]) -> Result<(), NativeError> {
        self.start(p, d, c, n)
    }
    fn binary(&mut self, i: usize, v: &[u8]) -> Result<(), NativeError> {
        self.domain(i, Some(v))
    }
    fn short(&mut self, i: usize, v: &[i64]) -> Result<(), NativeError> {
        self.short_domain(i, Some(v))
    }
    fn scalar(&mut self, row: ScalarRow<'_>) -> Result<(), NativeError> {
        self.scalar_row(row)
    }
    fn linear(&mut self, terms: &[(Vec<i64>, usize)], rhs: &[i64]) -> Result<(), NativeError> {
        self.linear_row(terms, rhs, true)
    }
    fn selection(&mut self, row: SelectionRow) -> Result<(), NativeError> {
        self.selection_row(row)
    }
    fn finish(&mut self, c: SubmissionCounts) -> Result<(), NativeError> {
        self.complete(c)
    }
}
impl StatementSink for Context {
    type Error = NativeError;
    fn begin(&mut self, p: i128, d: usize, c: SubmissionCounts, n: &[u64]) -> Result<(), NativeError> {
        self.start(p, d, c, n)
    }
    fn binary_domain(&mut self, i: usize) -> Result<(), NativeError> {
        self.domain(i, None)
    }
    fn short_domain(&mut self, i: usize) -> Result<(), NativeError> {
        Context::short_domain(self, i, None)
    }
    fn scalar(&mut self, row: ScalarRow<'_>) -> Result<(), NativeError> {
        self.scalar_row(row)
    }
    fn linear(&mut self, terms: &[(Vec<i64>, usize)], rhs: &[i64]) -> Result<(), NativeError> {
        self.linear_row(terms, rhs, true)
    }
    fn selection(&mut self, row: SelectionRow) -> Result<(), NativeError> {
        self.selection_row(row)
    }
    fn finish(&mut self, c: SubmissionCounts) -> Result<(), NativeError> {
        self.complete(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sparse_scalar_preparation_matches_dense_reference_and_overflow_rules() {
        fn reference(row: &ScalarRow<'_>) -> Result<(Vec<usize>, Vec<i64>), NativeError> {
            if row.terms.is_empty() { return Err(NativeError::InvalidRelation); }
            let mut grouped: BTreeMap<usize, Vec<i64>> = BTreeMap::new();
            for &(a, p, i) in row.terms {
                if i >= Poly::D { return Err(NativeError::InvalidRelation); }
                let v = grouped.entry(p).or_insert_with(|| vec![0i64; Poly::D]);
                v[i] = v[i].checked_add(a).ok_or(NativeError::InvalidRelation)?;
            }
            let mut indices = Vec::new();
            let mut coefficients = Vec::new();
            for (p, mut v) in grouped {
                indices.push(p);
                v[1..].reverse();
                for a in &mut v[1..] { *a = a.checked_neg().ok_or(NativeError::InvalidRelation)?; }
                coefficients.extend(v.into_iter().map(|a| {
                    ((i128::from(a) + PROOF_MODULUS / 2).rem_euclid(PROOF_MODULUS)
                        - PROOF_MODULUS / 2) as i64
                }));
            }
            Ok((indices, coefficients))
        }
        let mut cases = vec![
            vec![], vec![(1, 0, Poly::D)],
            vec![(1, 3, 255), (-1, 3, 255)],
            vec![(i64::MIN, 0, 0), (i64::MAX, 1, 255)],
            vec![(i64::MIN, 0, 1)],
            vec![(i64::MIN, 0, 1), (i64::MAX, 0, 1)],
            vec![(i64::MAX, 0, 1), (1, 0, 1), (-1, 0, 1)],
            vec![(i64::MIN, 0, 0), (-1, 0, 0)],
        ];
        let mut state = 0x6a09e667f3bcc909u64;
        for length in (1..10).cycle().take(4096) {
            let mut terms = Vec::new();
            for _ in 0..length {
                state ^= state << 13; state ^= state >> 7; state ^= state << 17;
                terms.push(((state % 31) as i64 - 15, (state >> 8) as usize % 6,
                    [0, 1, 17, 255][(state >> 16) as usize % 4]));
            }
            cases.push(terms);
        }
        for terms in cases {
            let row = ScalarRow { terms: &terms, rhs: 0 };
            assert_eq!(scalar_coefficients(&row), reference(&row));
        }
    }

    #[test]
    fn public_coefficient_normalization_matches_wide_reference() {
        let q = NATIVE_MODULUS;
        let values = [i64::MIN, i64::MIN + 1, -q - 1, -q, -1, 0, 1,
            q / 2, q / 2 + 1, q - 1, q, q + 1, i64::MAX];
        for residue in [0, 1, q / 2, q / 2 + 1, q - 1] {
            for value in values {
                let expected = (i128::from(residue) + i128::from(value))
                    .rem_euclid(PROOF_MODULUS);
                let actual = add_public_coefficient(residue, value);
                assert_eq!(i128::from(actual), expected);
                let centered = (expected + PROOF_MODULUS / 2)
                    .rem_euclid(PROOF_MODULUS) - PROOF_MODULUS / 2;
                assert_eq!(i128::from(center_public_coefficient(actual)), centered);
            }
        }
        // Repeated duplicate handles retain canonical residues at every step.
        let mut actual = 0;
        let mut expected = 0i128;
        for value in values.into_iter().cycle().take(4096) {
            actual = add_public_coefficient(actual, value);
            expected = (expected + i128::from(value)).rem_euclid(PROOF_MODULUS);
            assert_eq!(i128::from(actual), expected);
        }
    }

    #[test]
    fn native_private_gaussian_uses_integer_sampler_and_clears_registration() {
        use super::super::portable::{expansion::CounterExpander, gaussian_exact::{gaussian_i32, SamplingBudget}};
        let context = Context::new(false, NativeBudget { max_native_bytes: 1 << 20 }).unwrap();
        let key = [11u8; 32];
        for count in [1, 2] {
            for scale in [0, 12, 26] {
                let mut output = vec![0i64; count * 256];
                assert_eq!(unsafe { ffi::quil_fixture_sample_prg(key.as_ptr(), 7, count, scale, 4, output.as_mut_ptr()) }, 0);
                let mut stream = CounterExpander::aes256(&key, 7);
                let expected = gaussian_i32(&mut stream, count * 256, scale, SamplingBudget {
                    max_steps: count * 256 * 4096, max_random_bytes: count * 256 * 4096 + 512,
                    max_coefficients: count * 256,
                }).unwrap();
                assert!(output.iter().zip(expected.iter()).all(|(&actual, &expected)| actual == i64::from(expected)));
            }
        }
        drop(context);
        let _guard = NATIVE_STATE.lock().unwrap();
        let mut output = [99i64; 256];
        assert_eq!(unsafe { ffi::quil_fixture_sample_prg(key.as_ptr(), 7, 1, 0, 4, output.as_mut_ptr()) }, 1);
        assert_eq!(output, [99; 256]);
    }

    #[test]
    fn native_private_rejection_uses_exact_registered_decisions() {
        use super::super::portable::{expansion::CounterExpander, rejection::{decide_256, RejectionKind, RejectionParameters}};
        let context = Context::new(false, NativeBudget { max_native_bytes: 1 << 20 }).unwrap();
        let key = [7u8; 32];
        let parameters = RejectionParameters::from_binary64(64.0, 2.0).unwrap();
        for (kind, mode) in [(RejectionKind::Standard, 0), (RejectionKind::SignFiltered, 1), (RejectionKind::Bimodal, 2)] {
            for zv in [-20, 0, 20] {
                let mut stream = CounterExpander::aes256(&key, 9);
                let mut bytes = [0; 512];
                stream.squeeze(&mut bytes).unwrap();
                let expected = decide_256(kind, zv, 4, bytes[..32].try_into().unwrap(), &parameters).unwrap();
                assert_eq!(unsafe { ffi::quil_fixture_exact_rejection(key.as_ptr(), 9, mode, zv, 4, 8.0, 2.0) }, i32::from(expected));
            }
        }
        assert_eq!(unsafe { ffi::quil_fixture_exact_rejection(key.as_ptr(), 9, 0, i64::MAX, 0, 8.0, 2.0) }, -1);
        assert_eq!(unsafe { ffi::quil_fixture_exact_rejection(key.as_ptr(), 9, 0, 0, 0, 8.0, 0.5) }, -1);
        drop(context);
        let _guard = NATIVE_STATE.lock().unwrap();
        assert_eq!(unsafe { ffi::quil_fixture_exact_rejection(key.as_ptr(), 9, 0, 0, 0, 8.0, 2.0) }, -1);
    }

    #[test]
    fn native_rows_cover_conjugation_duplicate_handles_and_public_domains() {
        let budget = NativeBudget {
            max_native_bytes: 1 << 20,
        };
        let counts = SubmissionCounts {
            original_binary_polynomials: 4,
            scalar_equations: 1,
            linear_equations: 1,
            selection_equations: 1,
            ..Default::default()
        };
        for (selector, valid) in [(0, true), (1, true), (1, false)] {
            let mut c = Context::new(false, budget).unwrap();
            c.start(PROOF_MODULUS, 256, counts, &[]).unwrap();
            let mut zero = [0; 256];
            zero[0] = 1;
            zero[255] = 1;
            let mut one = [0; 256];
            one[7] = 1;
            let mut selected = if selector == 0 { zero } else { one };
            if !valid {
                selected[0] ^= 1;
            }
            let mut choice = [0; 256];
            choice[0] = selector;
            for (i, p) in [choice, zero, one, selected].iter().enumerate() {
                c.domain(i, Some(p)).unwrap();
            }
            c.scalar_row(ScalarRow {
                terms: &[(2, 1, 0), (-7, 1, 255), (3, 2, 7)],
                rhs: -2,
            })
            .unwrap();
            let mut plus = vec![0; 256];
            plus[0] = 3;
            let mut minus = vec![0; 256];
            minus[0] = -2;
            c.linear_row(&[(plus, 1), (minus, 1)], &zero.map(i64::from), true)
                .unwrap();
            c.selection_row(SelectionRow {
                selector: 0,
                terms: vec![(1, 1, 2, 3)],
            })
            .unwrap();
            c.complete(counts).unwrap();
            assert_eq!(
                unsafe { ffi::quil_fixture_check(c.ready().unwrap()) },
                i32::from(valid)
            );
        }
        let mut public = Context::new(true, budget).unwrap();
        public.start(PROOF_MODULUS, 256, counts, &[]).unwrap();
        assert_eq!(
            public.domain(0, Some(&[0; 256])),
            Err(NativeError::InvalidRelation)
        );
        public.domain(0, None).unwrap();
        assert_eq!(public.complete(counts), Err(NativeError::InvalidRelation));
        assert_eq!(
            unsafe { ffi::quil_fixture_check_count(public.ptr().unwrap()) },
            0
        );
    }

    #[test]
    fn rejected_submission_releases_context_and_global_lock() {
        let counts = SubmissionCounts {
            original_binary_polynomials: 1,
            linear_equations: 1,
            ..Default::default()
        };
        {
            let mut c = Context::new(
                false,
                NativeBudget {
                    max_native_bytes: 1536,
                },
            )
            .unwrap();
            c.start(PROOF_MODULUS, 256, counts, &[]).unwrap();
            c.domain(0, Some(&[0; 256])).unwrap();
            assert_eq!(
                c.linear_row(&[(vec![0; 256], 0)], &[0; 256], true),
                Err(NativeError::AllocationBudget)
            );
            assert_eq!(c.ready(), Err(NativeError::InvalidRelation));
        }
        let c = Context::new(
            true,
            NativeBudget {
                max_native_bytes: 1 << 20,
            },
        )
        .unwrap();
        assert!(c.pointer.is_none());
    }
}
