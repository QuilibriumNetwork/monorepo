//! Reference extension commitment equations and their rank-one aggregation.
//! The public key is borrowed immutably by the equation so direct evaluation
//! and aggregation use the same key. This alone does not establish binding.
use super::super::commitment::{aggregate_extension_rows, extension_product_sum};
use super::*;

pub struct CommitmentTerm {
    pub key_offset: usize,
    pub witness_offset: usize,
    pub witness_count: usize,
    pub scalar: i64,
}

/// Each coefficient multiplies the next rank witness polynomials componentwise.
/// This is distinct from extension multiplication by the commitment key.
pub struct ComponentwisePart {
    pub witness_offset: usize,
    pub coefficients: Vec<ProofPolynomial>,
}

pub struct CommitmentConstraint<'key> {
    pub(super) layout: WitnessLayout,
    key: &'key [ProofPolynomial],
    rank: usize,
    terms: Vec<CommitmentTerm>,
    parts: Vec<ComponentwisePart>,
    target: Vec<ProofPolynomial>,
}

fn within(offset: usize, length: usize, total: usize) -> Result<(), ConstraintError> {
    offset
        .checked_add(length)
        .filter(|&end| end <= total)
        .map(|_| ())
        .ok_or(ConstraintError::Layout)
}

fn scalar(value: i64) -> ProofPolynomial {
    let mut coefficients = [0; DEGREE];
    coefficients[0] = value;
    ProofPolynomial::from_signed(&coefficients).unwrap()
}

impl<'key> CommitmentConstraint<'key> {
    pub fn new(
        layout: &WitnessLayout,
        key: &'key [ProofPolynomial],
        rank: usize,
        terms: Vec<CommitmentTerm>,
        parts: Vec<ComponentwisePart>,
        target: Vec<ProofPolynomial>,
    ) -> Result<Self, ConstraintError> {
        if rank == 0 || rank > 32 {
            return Err(ConstraintError::Rank);
        }
        if target.len() != rank {
            return Err(ConstraintError::Length);
        }
        let degree = rank.next_power_of_two();
        for term in &terms {
            within(term.witness_offset, term.witness_count, layout.count)?;
            let padded = term
                .witness_count
                .checked_add(degree - 1)
                .ok_or(ConstraintError::Length)?
                / degree
                * degree;
            within(term.key_offset, padded, key.len())?;
        }
        for part in &parts {
            let length = part
                .coefficients
                .len()
                .checked_mul(rank)
                .ok_or(ConstraintError::Length)?;
            within(part.witness_offset, length, layout.count)?;
        }
        Ok(Self {
            layout: layout.clone(),
            key,
            rank,
            terms,
            parts,
            target,
        })
    }

    pub fn challenge_count(&self) -> usize {
        self.rank
    }

    pub fn evaluate(
        &self,
        witness: &[ProofPolynomial],
    ) -> Result<Vec<ProofPolynomial>, ConstraintError> {
        if witness.len() != self.layout.count {
            return Err(ConstraintError::Length);
        }
        let mut result: Vec<_> = self.target.iter().map(|value| zero().sub(value)).collect();
        for term in &self.terms {
            let product = extension_product_sum(
                &self.key[term.key_offset..],
                &witness[term.witness_offset..term.witness_offset + term.witness_count],
                self.rank,
            )
            .map_err(|_| ConstraintError::Length)?;
            let scale = scalar(term.scalar);
            for (value, product) in result.iter_mut().zip(&product) {
                *value = value.add(&scale.mul(product));
            }
        }
        for part in &self.parts {
            for (index, coefficient) in part.coefficients.iter().enumerate() {
                for (row, value) in result.iter_mut().enumerate() {
                    *value = value.add(
                        &coefficient.mul(&witness[part.witness_offset + index * self.rank + row]),
                    );
                }
            }
        }
        Ok(result)
    }

    pub fn check(&self, witness: &[ProofPolynomial]) -> Result<bool, ConstraintError> {
        Ok(self
            .evaluate(witness)?
            .iter()
            .all(|poly| poly.0.iter().all(|&value| value == 0)))
    }

    pub fn aggregate(
        &self,
        challenges: &[ProofPolynomial],
    ) -> Result<SparseConstraint, ConstraintError> {
        if challenges.len() != self.rank {
            return Err(ConstraintError::Length);
        }
        let mut linear = Vec::new();
        for term in &self.terms {
            let scale = scalar(term.scalar);
            let scaled: Vec<_> = challenges
                .iter()
                .map(|challenge| challenge.mul(&scale))
                .collect();
            let coefficients =
                aggregate_extension_rows(&self.key[term.key_offset..], &scaled, term.witness_count)
                    .map_err(|error| match error {
                        super::super::commitment::CommitmentError::Allocation => {
                            ConstraintError::Allocation
                        }
                        _ => ConstraintError::Length,
                    })?;
            linear.push(LinearPart {
                offset: term.witness_offset,
                coefficients,
            });
        }
        for part in &self.parts {
            let coefficients = part
                .coefficients
                .iter()
                .flat_map(|coefficient| {
                    challenges
                        .iter()
                        .map(move |challenge| coefficient.mul(challenge))
                })
                .collect();
            linear.push(LinearPart {
                offset: part.witness_offset,
                coefficients,
            });
        }
        let mut target = zero();
        for (challenge, value) in challenges.iter().zip(&self.target) {
            target = target.add(&challenge.mul(value));
        }
        SparseConstraint::new(&self.layout, EquationDomain::Ring, linear, vec![], target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn polynomials(count: usize, salt: usize) -> Vec<ProofPolynomial> {
        (0..count)
            .map(|i| {
                let mut values = [0; DEGREE];
                values[0] = (i + salt) as i64;
                values[(i * 19 + 255) % DEGREE] += 7;
                values[(i * 29 + 1) % DEGREE] -= 11;
                ProofPolynomial::from_signed(&values).unwrap()
            })
            .collect()
    }

    #[test]
    fn rotation_transpose_matches_extension_products_at_partial_ranks_and_tails() {
        for rank in [1usize, 3, 4, 5] {
            let count = rank.next_power_of_two() + 1;
            let padded = 2 * rank.next_power_of_two();
            let key = polynomials(padded, 17);
            let witness = polynomials(count, 31);
            let challenges = polynomials(rank, 43);
            let product = extension_product_sum(&key, &witness, rank).unwrap();
            let coefficients = aggregate_extension_rows(&key, &challenges, count).unwrap();
            let mut direct = zero();
            for (c, p) in challenges.iter().zip(product) {
                direct = direct.add(&c.mul(&p));
            }
            let mut transposed = zero();
            for (c, w) in coefficients.iter().zip(&witness) {
                transposed = transposed.add(&c.mul(w));
            }
            assert_eq!(direct.reference_bitpack(), transposed.reference_bitpack());
        }
    }

    #[test]
    fn commitment_equation_aggregates_offsets_scalars_and_componentwise_parts() {
        let layout = WitnessLayout::new(&[5, 6]).unwrap();
        let key = polynomials(10, 23);
        let witness = polynomials(11, 37);
        let make = |target| {
            CommitmentConstraint::new(
                &layout,
                &key,
                3,
                vec![
                    CommitmentTerm {
                        key_offset: 1,
                        witness_offset: 0,
                        witness_count: 5,
                        scalar: -3,
                    },
                    CommitmentTerm {
                        key_offset: 0,
                        witness_offset: 1,
                        witness_count: 3,
                        scalar: 2,
                    },
                ],
                vec![ComponentwisePart {
                    witness_offset: 5,
                    coefficients: polynomials(2, 47),
                }],
                target,
            )
            .unwrap()
        };
        let expected = make(vec![zero(), zero(), zero()])
            .evaluate(&witness)
            .unwrap();
        let equation = make(expected);
        assert!(equation.check(&witness).unwrap());
        let challenges = polynomials(3, 59);
        let aggregate = equation.aggregate(&challenges).unwrap();
        assert!(aggregate.check(&witness).unwrap());
        let mut changed = witness;
        changed[10] = changed[10].add(&scalar(1));
        assert!(!equation.check(&changed).unwrap());
        let mut direct = zero();
        for (challenge, residual) in challenges.iter().zip(equation.evaluate(&changed).unwrap()) {
            direct = direct.add(&challenge.mul(&residual));
        }
        assert_eq!(
            direct.reference_bitpack(),
            aggregate.evaluate(&changed).unwrap().reference_bitpack()
        );
        assert!(!aggregate.check(&changed).unwrap());
    }

    #[test]
    fn malformed_commitment_shapes_fail_before_arithmetic() {
        let layout = WitnessLayout::new(&[5]).unwrap();
        let key = polynomials(7, 1);
        assert!(matches!(
            CommitmentConstraint::new(
                &layout,
                &key,
                3,
                vec![CommitmentTerm {
                    key_offset: 0,
                    witness_offset: 0,
                    witness_count: 5,
                    scalar: 1
                }],
                vec![],
                polynomials(3, 0)
            ),
            Err(ConstraintError::Layout)
        ));
        assert!(matches!(
            CommitmentConstraint::new(
                &layout,
                &key,
                3,
                vec![],
                vec![ComponentwisePart {
                    witness_offset: 0,
                    coefficients: polynomials(2, 0)
                }],
                polynomials(3, 0)
            ),
            Err(ConstraintError::Layout)
        ));
        assert!(matches!(
            aggregate_extension_rows(&key, &[], 0),
            Err(super::super::super::commitment::CommitmentError::Rank)
        ));
        let equation =
            CommitmentConstraint::new(&layout, &key, 3, vec![], vec![], polynomials(3, 0)).unwrap();
        assert_eq!(equation.challenge_count(), 3);
        assert!(matches!(
            equation.aggregate(&[]),
            Err(ConstraintError::Length)
        ));
        assert!(matches!(
            equation.evaluate(&[]),
            Err(ConstraintError::Length)
        ));
    }
}
