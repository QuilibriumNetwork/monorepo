//! Conjugated witness-view and integer-slot constraints from the reference
//! composition. Aggregated checks constrain only a constant coefficient;
//! their challenges must be supplied by the complete public transcript.
use super::*;

fn checked_end(
    layout: &WitnessLayout,
    offset: usize,
    length: usize,
) -> Result<(), ConstraintError> {
    offset
        .checked_add(length)
        .filter(|&end| end <= layout.count)
        .map(|_| ())
        .ok_or(ConstraintError::Layout)
}

/// c * conjugate(witness[source..]) = witness[target..]. The optional
/// multiplier is a public polynomial; absence means one.
pub struct ConjugationConstraint {
    pub(super) layout: WitnessLayout,
    source: usize,
    target: usize,
    length: usize,
    multiplier: Option<ProofPolynomial>,
}

impl ConjugationConstraint {
    pub fn new(
        layout: &WitnessLayout,
        source: usize,
        target: usize,
        length: usize,
        multiplier: Option<ProofPolynomial>,
    ) -> Result<Self, ConstraintError> {
        checked_end(layout, source, length)?;
        checked_end(layout, target, length)?;
        Ok(Self {
            layout: layout.clone(),
            source,
            target,
            length,
            multiplier,
        })
    }

    pub fn challenge_count(&self) -> usize {
        self.length
    }

    pub fn check(&self, witness: &[ProofPolynomial]) -> Result<bool, ConstraintError> {
        if witness.len() != self.layout.count {
            return Err(ConstraintError::Length);
        }
        for index in 0..self.length {
            let conjugate = witness[self.source + index].conjugate();
            let expected = match &self.multiplier {
                Some(multiplier) => multiplier.mul(&conjugate),
                None => conjugate,
            };
            if expected.0 != witness[self.target + index].0 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// ct(sum alpha*(target-c*conjugate(source))) is represented using
    /// -conjugate(c*alpha) at source and +alpha at target. Overlapping views
    /// remain separate linear parts and are summed by SparseConstraint.
    pub fn aggregate(
        &self,
        challenges: &[ProofPolynomial],
    ) -> Result<SparseConstraint, ConstraintError> {
        if challenges.len() != self.length {
            return Err(ConstraintError::Length);
        }
        let negative = challenges
            .iter()
            .map(|challenge| {
                let product = match &self.multiplier {
                    Some(multiplier) => multiplier.mul(challenge),
                    None => zero().add(challenge),
                };
                zero().sub(&product.conjugate())
            })
            .collect();
        let positive = challenges
            .iter()
            .map(|challenge| zero().add(challenge))
            .collect();
        SparseConstraint::new(
            &self.layout,
            EquationDomain::ConstantCoefficient,
            vec![
                LinearPart {
                    offset: self.source,
                    coefficients: negative,
                },
                LinearPart {
                    offset: self.target,
                    coefficients: positive,
                },
            ],
            vec![],
            zero(),
        )
    }
}

/// An extension slot holding a base-field integer: only the constant
/// coefficient of the first polynomial may be nonzero; all later polynomials
/// in the slot must be zero. This does not impose an integer range bound.
pub struct IntegerSlotConstraint {
    pub(super) layout: WitnessLayout,
    offset: usize,
    rank: usize,
    challenge_count: usize,
}

impl IntegerSlotConstraint {
    pub fn new(
        layout: &WitnessLayout,
        offset: usize,
        rank: usize,
    ) -> Result<Self, ConstraintError> {
        if rank == 0 {
            return Err(ConstraintError::Length);
        }
        checked_end(layout, offset, rank)?;
        let challenge_count = rank
            .checked_mul(DEGREE)
            .and_then(|count| count.checked_sub(1))
            .ok_or(ConstraintError::Length)?;
        Ok(Self {
            layout: layout.clone(),
            offset,
            rank,
            challenge_count,
        })
    }

    pub fn challenge_count(&self) -> usize {
        self.challenge_count
    }

    pub fn check(&self, witness: &[ProofPolynomial]) -> Result<bool, ConstraintError> {
        if witness.len() != self.layout.count {
            return Err(ConstraintError::Length);
        }
        for index in 0..self.rank {
            let start = usize::from(index == 0);
            if witness[self.offset + index].0[start..]
                .iter()
                .any(|&value| value != 0)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Exact pinned intcnst_aggregate_add coefficient order. This is ct(phi*w),
    /// not a coefficient-wise dot product: negacyclic signs/reversal matter.
    pub fn aggregate(&self, challenges: &[i64]) -> Result<SparseConstraint, ConstraintError> {
        if challenges.len() != self.challenge_count {
            return Err(ConstraintError::Length);
        }
        let mut coefficients = Vec::new();
        coefficients
            .try_reserve_exact(self.rank)
            .map_err(|_| ConstraintError::Allocation)?;
        let mut used = 0;
        for index in 0..self.rank {
            let start = usize::from(index == 0);
            let mut polynomial = [0; DEGREE];
            polynomial[start..].copy_from_slice(&challenges[used..used + DEGREE - start]);
            used += DEGREE - start;
            coefficients.push(ProofPolynomial::from_signed(&polynomial).unwrap());
        }
        SparseConstraint::new(
            &self.layout,
            EquationDomain::ConstantCoefficient,
            vec![LinearPart {
                offset: self.offset,
                coefficients,
            }],
            vec![],
            zero(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::MODULUS;
    use super::*;

    fn poly(terms: &[(usize, i64)]) -> ProofPolynomial {
        let mut values = [0; DEGREE];
        for &(index, value) in terms {
            values[index] = value;
        }
        ProofPolynomial::from_signed(&values).unwrap()
    }

    #[test]
    fn conjugation_aggregation_matches_direct_residual_with_multiplier() {
        let layout = WitnessLayout::new(&[2, 2]).unwrap();
        let multiplier = poly(&[(0, 3), (1, -5), (255, 7)]);
        let left = [
            poly(&[(0, 2), (1, 11), (255, -17)]),
            poly(&[(7, -4), (128, 9)]),
        ];
        let right = left
            .iter()
            .map(|value| multiplier.mul(&value.conjugate()))
            .collect::<Vec<_>>();
        let mut witness = Vec::from(left);
        witness.extend(right);
        let challenges = [
            poly(&[(0, 19), (1, 23), (255, 31)]),
            poly(&[(7, -13), (128, 29)]),
        ];
        let equation = ConjugationConstraint::new(&layout, 0, 2, 2, Some(multiplier)).unwrap();
        assert!(equation.check(&witness).unwrap());
        let aggregate = equation.aggregate(&challenges).unwrap();
        assert!(aggregate.check(&witness).unwrap());
        witness[2] = witness[2].add(&poly(&[(1, 1)]));
        assert!(!equation.check(&witness).unwrap());
        // Only added X contributes: ct(alpha_0*X) = -alpha_0[255] = -31.
        assert_eq!(aggregate.evaluate(&witness).unwrap().0[0], MODULUS - 31);
        assert!(!aggregate.check(&witness).unwrap());
    }

    #[test]
    fn overlapping_conjugate_views_and_exact_challenge_counts() {
        let layout = WitnessLayout::new(&[1]).unwrap();
        let equation = ConjugationConstraint::new(&layout, 0, 0, 1, None).unwrap();
        let challenge = [poly(&[(1, 1)])];
        let aggregate = equation.aggregate(&challenge).unwrap();
        assert!(equation.check(&[poly(&[(0, 7)])]).unwrap());
        let witness = [poly(&[(1, 1)])];
        assert!(!equation.check(&witness).unwrap());
        assert!(!aggregate.check(&witness).unwrap());
        assert_eq!(equation.challenge_count(), 1);
        assert!(matches!(
            equation.aggregate(&[]),
            Err(ConstraintError::Length)
        ));
        assert!(matches!(
            ConjugationConstraint::new(&layout, usize::MAX, 0, 1, None),
            Err(ConstraintError::Layout)
        ));
        assert!(matches!(equation.check(&[]), Err(ConstraintError::Length)));
    }

    #[test]
    fn integer_slot_aggregation_covers_every_disallowed_coefficient() {
        let layout = WitnessLayout::new(&[3]).unwrap();
        let equation = IntegerSlotConstraint::new(&layout, 1, 2).unwrap();
        let mut witness = vec![poly(&[(255, 123)]), poly(&[(0, 17)]), zero()];
        assert!(equation.check(&witness).unwrap());
        let challenges: Vec<i64> = (1..=511).collect();
        assert_eq!(equation.challenge_count(), challenges.len());
        let aggregate = equation.aggregate(&challenges).unwrap();
        assert!(aggregate.check(&witness).unwrap());
        // First polynomial: phi[0]=0, phi[k]=k for k>0.
        witness[1] = witness[1].add(&poly(&[(1, 2), (255, 3)]));
        // Second polynomial: phi[k]=256+k, including its constant coefficient.
        witness[2] = poly(&[(0, 5), (1, 7)]);
        let expected = -2i64 * 255 - 3 + 5 * 256 - 7 * 511;
        assert_eq!(
            aggregate.evaluate(&witness).unwrap().0[0],
            i128::from(expected).rem_euclid(i128::from(MODULUS)) as u64
        );
        assert!(!equation.check(&witness).unwrap());
        assert!(!aggregate.check(&witness).unwrap());
        assert!(matches!(
            equation.aggregate(&challenges[..510]),
            Err(ConstraintError::Length)
        ));
        assert!(matches!(
            IntegerSlotConstraint::new(&layout, 0, 0),
            Err(ConstraintError::Length)
        ));
        assert!(matches!(
            IntegerSlotConstraint::new(&layout, 2, 2),
            Err(ConstraintError::Layout)
        ));
    }
}
