//! Rank-one sparse equations for the portable proof composition.
//! Full ring equations and constant-coefficient equations are distinct domains:
//! multiplying the latter by a polynomial challenge is generally invalid.
//! This is equation arithmetic, not a proof verifier or a constraint compiler.
use super::{ProofPolynomial, DEGREE};
use std::ops::Range;
use zeroize::Zeroizing;

pub mod bindings;
pub mod commitments;
pub mod sets;
pub mod vanishing;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessLayout {
    groups: Vec<Range<usize>>,
    count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EquationDomain {
    Ring,
    ConstantCoefficient,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConstraintError {
    Rank,
    Length,
    Layout,
    Domain,
    Allocation,
}

impl WitnessLayout {
    pub fn new(lengths: &[usize]) -> Result<Self, ConstraintError> {
        let mut groups = Vec::new();
        groups
            .try_reserve_exact(lengths.len())
            .map_err(|_| ConstraintError::Allocation)?;
        let mut count = 0usize;
        for &length in lengths {
            let end = count.checked_add(length).ok_or(ConstraintError::Length)?;
            groups.push(count..end);
            count = end;
        }
        Ok(Self { groups, count })
    }
    pub fn polynomial_count(&self) -> usize {
        self.count
    }
}

/// A linear inner product over consecutive flattened witness polynomials.
pub struct LinearPart {
    pub offset: usize,
    pub coefficients: Vec<ProofPolynomial>,
}

/// Coefficient times the inner product of two witness groups. As in pinned
/// quadfunc_eval_add, unequal group lengths use their common prefix. A caller
/// needing a different pairing must encode it explicitly in its public layout.
pub struct QuadraticTerm {
    pub left_group: usize,
    pub right_group: usize,
    pub coefficient: ProofPolynomial,
}

pub struct SparseConstraint {
    layout: WitnessLayout,
    domain: EquationDomain,
    linear: Vec<LinearPart>,
    quadratic: Vec<QuadraticTerm>,
    target: ProofPolynomial,
}

impl SparseConstraint {
    pub fn new(
        layout: &WitnessLayout,
        domain: EquationDomain,
        linear: Vec<LinearPart>,
        quadratic: Vec<QuadraticTerm>,
        target: ProofPolynomial,
    ) -> Result<Self, ConstraintError> {
        for part in &linear {
            if part
                .offset
                .checked_add(part.coefficients.len())
                .filter(|&end| end <= layout.count)
                .is_none()
            {
                return Err(ConstraintError::Layout);
            }
        }
        if quadratic.iter().any(|term| {
            term.left_group >= layout.groups.len() || term.right_group >= layout.groups.len()
        }) {
            return Err(ConstraintError::Layout);
        }
        Ok(Self {
            layout: layout.clone(),
            domain,
            linear,
            quadratic,
            target,
        })
    }

    /// Both the linear and quadratic views are derived from the same supplied
    /// witness and checked public layout; callers cannot provide divergent views.
    pub fn evaluate(
        &self,
        witness: &[ProofPolynomial],
    ) -> Result<ProofPolynomial, ConstraintError> {
        if witness.len() != self.layout.count {
            return Err(ConstraintError::Length);
        }
        let mut value = zero();
        for part in &self.linear {
            for (coefficient, polynomial) in part.coefficients.iter().zip(&witness[part.offset..]) {
                value = value.add(&coefficient.mul(polynomial));
            }
        }
        for term in &self.quadratic {
            let left = &witness[self.layout.groups[term.left_group].clone()];
            let right = &witness[self.layout.groups[term.right_group].clone()];
            let mut inner = zero();
            for (a, b) in left.iter().zip(right) {
                inner = inner.add(&a.mul(b));
            }
            value = value.add(&term.coefficient.mul(&inner));
        }
        Ok(value.sub(&self.target))
    }

    pub fn check(&self, witness: &[ProofPolynomial]) -> Result<bool, ConstraintError> {
        let residual = self.evaluate(witness)?;
        Ok(match self.domain {
            EquationDomain::Ring => residual.0.iter().all(|&v| v == 0),
            EquationDomain::ConstantCoefficient => residual.0[0] == 0,
        })
    }

    /// Ring challenge aggregation is valid only for a full ring equation.
    pub fn scale_by_ring(&self, challenge: &ProofPolynomial) -> Result<Self, ConstraintError> {
        if self.domain != EquationDomain::Ring {
            return Err(ConstraintError::Domain);
        }
        Ok(self.scaled(challenge))
    }

    /// Integer challenges preserve constant-coefficient equations as well.
    pub fn scale_by_scalar(&self, challenge: i64) -> Self {
        let mut coefficients = [0; DEGREE];
        coefficients[0] = challenge;
        self.scaled(&ProofPolynomial::from_signed(&coefficients).unwrap())
    }

    fn scaled(&self, challenge: &ProofPolynomial) -> Self {
        Self {
            layout: self.layout.clone(),
            domain: self.domain,
            linear: self
                .linear
                .iter()
                .map(|part| LinearPart {
                    offset: part.offset,
                    coefficients: part.coefficients.iter().map(|c| c.mul(challenge)).collect(),
                })
                .collect(),
            quadratic: self
                .quadratic
                .iter()
                .map(|term| QuadraticTerm {
                    left_group: term.left_group,
                    right_group: term.right_group,
                    coefficient: term.coefficient.mul(challenge),
                })
                .collect(),
            target: self.target.mul(challenge),
        }
    }

    /// Duplicate and overlapping terms are summed, never overwritten. Public
    /// domains and complete witness layouts must match before aggregation.
    pub fn add(mut self, other: Self) -> Result<Self, ConstraintError> {
        if self.domain != other.domain {
            return Err(ConstraintError::Domain);
        }
        if self.layout != other.layout {
            return Err(ConstraintError::Layout);
        }
        self.linear
            .try_reserve(other.linear.len())
            .map_err(|_| ConstraintError::Allocation)?;
        self.quadratic
            .try_reserve(other.quadratic.len())
            .map_err(|_| ConstraintError::Allocation)?;
        self.linear.extend(other.linear);
        self.quadratic.extend(other.quadratic);
        self.target = self.target.add(&other.target);
        Ok(self)
    }
}

fn zero() -> ProofPolynomial {
    ProofPolynomial(Zeroizing::new(vec![0; DEGREE]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn polynomial(terms: &[(usize, i64)]) -> ProofPolynomial {
        let mut coefficients = [0; DEGREE];
        for &(index, value) in terms {
            coefficients[index] = value;
        }
        ProofPolynomial::from_signed(&coefficients).unwrap()
    }

    #[test]
    fn sparse_quadratic_and_overlapping_linear_terms_match_hand_equation() {
        // w=(X^255, X, 2, 3). Paired inner product is 2X^255+3X.
        // Multiply by X, add w0 twice, and w1 once:
        // -2 + 3X^2 + 2X^255 + X, exercising negacyclic wrap and overlap.
        let layout = WitnessLayout::new(&[2, 2]).unwrap();
        let witness = vec![
            polynomial(&[(255, 1)]),
            polynomial(&[(1, 1)]),
            polynomial(&[(0, 2)]),
            polynomial(&[(0, 3)]),
        ];
        let constraint = SparseConstraint::new(
            &layout,
            EquationDomain::Ring,
            vec![
                LinearPart {
                    offset: 0,
                    coefficients: vec![polynomial(&[(0, 1)]), polynomial(&[(0, 1)])],
                },
                LinearPart {
                    offset: 0,
                    coefficients: vec![polynomial(&[(0, 1)])],
                },
            ],
            vec![QuadraticTerm {
                left_group: 0,
                right_group: 1,
                coefficient: polynomial(&[(1, 1)]),
            }],
            polynomial(&[(0, -2), (1, 1), (2, 3), (255, 2)]),
        )
        .unwrap();
        assert!(constraint.check(&witness).unwrap());
        let mut changed = witness;
        changed[3] = polynomial(&[(0, 4)]);
        assert!(!constraint.check(&changed).unwrap());
    }

    #[test]
    fn constant_equations_cannot_be_promoted_to_ring_aggregation() {
        let layout = WitnessLayout::new(&[1]).unwrap();
        let scalar = SparseConstraint::new(
            &layout,
            EquationDomain::ConstantCoefficient,
            vec![LinearPart {
                offset: 0,
                coefficients: vec![polynomial(&[(0, 1)])],
            }],
            vec![],
            zero(),
        )
        .unwrap();
        let witness = vec![polynomial(&[(255, 1)])];
        assert!(scalar.check(&witness).unwrap());
        assert!(scalar.scale_by_scalar(-17).check(&witness).unwrap());
        assert!(matches!(
            scalar.scale_by_ring(&polynomial(&[(1, 1)])),
            Err(ConstraintError::Domain)
        ));
        let ring = SparseConstraint::new(
            &layout,
            EquationDomain::Ring,
            vec![LinearPart {
                offset: 0,
                coefficients: vec![polynomial(&[(0, 1)])],
            }],
            vec![],
            zero(),
        )
        .unwrap();
        assert!(!ring.check(&witness).unwrap());
        assert!(matches!(ring.add(scalar), Err(ConstraintError::Domain)));
    }

    #[test]
    fn weighted_aggregation_preserves_residuals_and_duplicate_quadratic_terms() {
        let layout = WitnessLayout::new(&[1]).unwrap();
        let make = || {
            SparseConstraint::new(
                &layout,
                EquationDomain::Ring,
                vec![LinearPart {
                    offset: 0,
                    coefficients: vec![polynomial(&[(1, 2)])],
                }],
                vec![QuadraticTerm {
                    left_group: 0,
                    right_group: 0,
                    coefficient: polynomial(&[(0, 3)]),
                }],
                polynomial(&[(0, 5)]),
            )
            .unwrap()
        };
        let witness = vec![polynomial(&[(0, 7), (255, -1)])];
        let a = polynomial(&[(1, 9)]);
        let b = polynomial(&[(0, -3), (255, 5)]);
        let expected = make().evaluate(&witness).unwrap().mul(&a.add(&b));
        let aggregate = make()
            .scale_by_ring(&a)
            .unwrap()
            .add(make().scale_by_ring(&b).unwrap())
            .unwrap();
        assert_eq!(
            aggregate.evaluate(&witness).unwrap().reference_bitpack(),
            expected.reference_bitpack()
        );
    }

    #[test]
    fn layout_and_offsets_are_checked_before_evaluation() {
        assert!(matches!(
            WitnessLayout::new(&[usize::MAX, 1]),
            Err(ConstraintError::Length)
        ));
        let layout = WitnessLayout::new(&[1, 2]).unwrap();
        assert!(matches!(
            SparseConstraint::new(
                &layout,
                EquationDomain::Ring,
                vec![LinearPart {
                    offset: usize::MAX,
                    coefficients: vec![zero()]
                }],
                vec![],
                zero()
            ),
            Err(ConstraintError::Layout)
        ));
        assert!(matches!(
            SparseConstraint::new(
                &layout,
                EquationDomain::Ring,
                vec![],
                vec![QuadraticTerm {
                    left_group: 2,
                    right_group: 0,
                    coefficient: zero()
                }],
                zero()
            ),
            Err(ConstraintError::Layout)
        ));
        let row = SparseConstraint::new(
            &layout,
            EquationDomain::Ring,
            vec![],
            vec![QuadraticTerm {
                left_group: 0,
                right_group: 1,
                coefficient: polynomial(&[(0, 1)]),
            }],
            polynomial(&[(0, 6)]),
        )
        .unwrap();
        assert!(row
            .check(&[
                polynomial(&[(0, 2)]),
                polynomial(&[(0, 3)]),
                polynomial(&[(0, 999)])
            ])
            .unwrap());
        assert!(matches!(row.evaluate(&[]), Err(ConstraintError::Length)));
        let other = SparseConstraint::new(
            &WitnessLayout::new(&[2, 1]).unwrap(),
            EquationDomain::Ring,
            vec![],
            vec![],
            zero(),
        )
        .unwrap();
        assert!(matches!(row.add(other), Err(ConstraintError::Layout)));
    }
}
