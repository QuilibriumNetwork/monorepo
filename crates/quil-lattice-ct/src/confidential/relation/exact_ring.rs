//! Exact coefficientwise integer equations submitted over the proof modulus.
//! Coefficients are constant polynomials; never normalize them modulo R_q.
use super::*;
use backend::{ring_lift::LiftError, PROOF_MODULUS};

#[derive(PartialEq, Eq)]
pub(super) struct ExactRingEquation {
    pub terms: Vec<(i64, usize)>,
    pub rhs: i64,
}

impl ExactRingEquation {
    /// Interval over the complete binary domain, including repeated handles.
    /// Treating repeated occurrences independently only enlarges the interval.
    pub fn checked_interval(&self, variables: usize) -> Result<(i128, i128), LiftError> {
        if self.terms.is_empty() || self.terms.iter().any(|&(_, i)| i >= variables) {
            return Err(LiftError::InvalidShape);
        }
        let mut lower = -i128::from(self.rhs);
        let mut upper = lower;
        for &(a, _) in &self.terms {
            lower = lower.checked_add(i128::from(a).min(0)).ok_or(LiftError::ResidualMayWrap)?;
            upper = upper.checked_add(i128::from(a).max(0)).ok_or(LiftError::ResidualMayWrap)?;
        }
        if lower <= -PROOF_MODULUS / 2 || upper >= PROOF_MODULUS / 2 {
            return Err(LiftError::ResidualMayWrap);
        }
        Ok((lower, upper))
    }

    pub fn validate(&self, binary: &[Poly]) -> bool {
        self.checked_interval(binary.len()).is_ok()
            && (0..Poly::D).all(|j| self.terms.iter().map(|&(a, i)| {
                i128::from(a) * i128::from(binary[i].c[j])
            }).sum::<i128>() == i128::from(self.rhs))
    }

    pub fn emitted(&self) -> (Vec<(Vec<i64>, usize)>, Vec<i64>) {
        let terms = self.terms.iter().map(|&(a, index)| {
            let mut polynomial = vec![0; Poly::D];
            polynomial[0] = a;
            (polynomial, index)
        }).collect();
        (terms, vec![self.rhs; Poly::D])
    }
}
