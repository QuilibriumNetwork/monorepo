//! Checked family aggregation with explicit challenge counts and ordering.
//! Challenges are supplied as complete vectors so a caller can sample one
//! protocol batch spanning multiple sets without changing the stream schedule.
use super::{
    bindings::{ConjugationConstraint, IntegerSlotConstraint},
    commitments::CommitmentConstraint,
    *,
};

pub struct RingConstraintSet<'key> {
    layout: WitnessLayout,
    sparse: Vec<SparseConstraint>,
    commitments: Vec<CommitmentConstraint<'key>>,
    challenges: usize,
}

impl<'key> RingConstraintSet<'key> {
    pub fn new(
        layout: &WitnessLayout,
        sparse: Vec<SparseConstraint>,
        commitments: Vec<CommitmentConstraint<'key>>,
    ) -> Result<Self, ConstraintError> {
        let mut challenges = sparse.len();
        for equation in &sparse {
            if equation.domain != EquationDomain::Ring {
                return Err(ConstraintError::Domain);
            }
            if &equation.layout != layout {
                return Err(ConstraintError::Layout);
            }
        }
        for equation in &commitments {
            if &equation.layout != layout {
                return Err(ConstraintError::Layout);
            }
            challenges = challenges
                .checked_add(equation.challenge_count())
                .ok_or(ConstraintError::Length)?;
        }
        Ok(Self {
            layout: layout.clone(),
            sparse,
            commitments,
            challenges,
        })
    }
    pub fn challenge_count(&self) -> usize {
        self.challenges
    }

    pub fn check(&self, witness: &[ProofPolynomial]) -> Result<bool, ConstraintError> {
        if witness.len() != self.layout.count {
            return Err(ConstraintError::Length);
        }
        for equation in &self.sparse {
            if !equation.check(witness)? {
                return Ok(false);
            }
        }
        for equation in &self.commitments {
            if !equation.check(witness)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Reference order: one challenge per rank-one sparse row, followed by
    /// rank challenges per commitment equation. Missing or surplus entries fail.
    pub fn aggregate(
        &self,
        challenges: &[ProofPolynomial],
    ) -> Result<SparseConstraint, ConstraintError> {
        if challenges.len() != self.challenges {
            return Err(ConstraintError::Length);
        }
        let mut result =
            SparseConstraint::new(&self.layout, EquationDomain::Ring, vec![], vec![], zero())?;
        for (equation, challenge) in self.sparse.iter().zip(challenges) {
            result = result.add(equation.scale_by_ring(challenge)?)?;
        }
        let mut used = self.sparse.len();
        for equation in &self.commitments {
            let end = used + equation.challenge_count();
            result = result.add(equation.aggregate(&challenges[used..end])?)?;
            used = end;
        }
        Ok(result)
    }
}

pub struct ScalarConstraintSet {
    layout: WitnessLayout,
    sparse: Vec<SparseConstraint>,
    conjugations: Vec<ConjugationConstraint>,
    integers: Vec<IntegerSlotConstraint>,
    scalar_challenges: usize,
    polynomial_challenges: usize,
}

impl ScalarConstraintSet {
    pub fn new(
        layout: &WitnessLayout,
        sparse: Vec<SparseConstraint>,
        conjugations: Vec<ConjugationConstraint>,
        integers: Vec<IntegerSlotConstraint>,
    ) -> Result<Self, ConstraintError> {
        let mut scalar_challenges = sparse.len();
        let mut polynomial_challenges = 0usize;
        for equation in &sparse {
            if equation.domain != EquationDomain::ConstantCoefficient {
                return Err(ConstraintError::Domain);
            }
            if &equation.layout != layout {
                return Err(ConstraintError::Layout);
            }
        }
        for equation in &conjugations {
            if &equation.layout != layout {
                return Err(ConstraintError::Layout);
            }
            polynomial_challenges = polynomial_challenges
                .checked_add(equation.challenge_count())
                .ok_or(ConstraintError::Length)?;
        }
        for equation in &integers {
            if &equation.layout != layout {
                return Err(ConstraintError::Layout);
            }
            scalar_challenges = scalar_challenges
                .checked_add(equation.challenge_count())
                .ok_or(ConstraintError::Length)?;
        }
        Ok(Self {
            layout: layout.clone(),
            sparse,
            conjugations,
            integers,
            scalar_challenges,
            polynomial_challenges,
        })
    }

    /// Scalar count includes integer-slot constraints, even when sparse is empty.
    pub fn challenge_counts(&self) -> (usize, usize) {
        (self.scalar_challenges, self.polynomial_challenges)
    }

    pub fn check(&self, witness: &[ProofPolynomial]) -> Result<bool, ConstraintError> {
        if witness.len() != self.layout.count {
            return Err(ConstraintError::Length);
        }
        for equation in &self.sparse {
            if !equation.check(witness)? {
                return Ok(false);
            }
        }
        for equation in &self.conjugations {
            if !equation.check(witness)? {
                return Ok(false);
            }
        }
        for equation in &self.integers {
            if !equation.check(witness)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Sparse scalar challenges come first; integer-slot scalar challenges follow.
    /// Conjugation challenges use the separate polynomial vector, in set order.
    pub fn aggregate(
        &self,
        scalars: &[i64],
        polynomials: &[ProofPolynomial],
    ) -> Result<SparseConstraint, ConstraintError> {
        if scalars.len() != self.scalar_challenges
            || polynomials.len() != self.polynomial_challenges
        {
            return Err(ConstraintError::Length);
        }
        let mut result = SparseConstraint::new(
            &self.layout,
            EquationDomain::ConstantCoefficient,
            vec![],
            vec![],
            zero(),
        )?;
        for (equation, &challenge) in self.sparse.iter().zip(scalars) {
            result = result.add(equation.scale_by_scalar(challenge))?;
        }
        let mut used = 0;
        for equation in &self.conjugations {
            let end = used + equation.challenge_count();
            result = result.add(equation.aggregate(&polynomials[used..end])?)?;
            used = end;
        }
        used = self.sparse.len();
        for equation in &self.integers {
            let end = used + equation.challenge_count();
            result = result.add(equation.aggregate(&scalars[used..end])?)?;
            used = end;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{transcript::ReferenceTranscript, MODULUS};
    use super::*;

    fn poly(index: usize, value: i64) -> ProofPolynomial {
        let mut coefficients = [0; DEGREE];
        coefficients[index] = value;
        ProofPolynomial::from_signed(&coefficients).unwrap()
    }

    #[test]
    fn scalar_set_includes_all_families_in_reference_challenge_order() {
        let layout = WitnessLayout::new(&[1, 1]).unwrap();
        let sparse = SparseConstraint::new(
            &layout,
            EquationDomain::ConstantCoefficient,
            vec![LinearPart {
                offset: 0,
                coefficients: vec![poly(0, 1)],
            }],
            vec![],
            poly(0, 7),
        )
        .unwrap();
        let conjugation = ConjugationConstraint::new(&layout, 0, 1, 1, None).unwrap();
        let integer = IntegerSlotConstraint::new(&layout, 1, 1).unwrap();
        let set = ScalarConstraintSet::new(&layout, vec![sparse], vec![conjugation], vec![integer])
            .unwrap();
        assert_eq!(set.challenge_counts(), (256, 1));
        let mut scalars = vec![0; 256];
        scalars[0] = 3;
        scalars[255] = 11;
        let aggregate = set.aggregate(&scalars, &[poly(255, 5)]).unwrap();
        assert!(set.check(&[poly(0, 7), poly(0, 7)]).unwrap());
        assert!(aggregate.check(&[poly(0, 7), poly(0, 7)]).unwrap());
        let changed = [poly(0, 9), poly(0, 7).add(&poly(1, 1))];
        // sparse: 3*2; conjugation: -5; integer: -11.
        assert_eq!(aggregate.evaluate(&changed).unwrap().0[0], MODULUS - 10);
        assert!(!set.check(&changed).unwrap());
        assert!(matches!(
            set.aggregate(&scalars[..255], &[poly(255, 5)]),
            Err(ConstraintError::Length)
        ));
        assert!(matches!(
            set.aggregate(&scalars, &[]),
            Err(ConstraintError::Length)
        ));
    }

    #[test]
    fn ring_set_uses_sparse_then_commitment_challenges_without_omission() {
        let layout = WitnessLayout::new(&[1]).unwrap();
        let key = [poly(0, 2)];
        let sparse = SparseConstraint::new(
            &layout,
            EquationDomain::Ring,
            vec![LinearPart {
                offset: 0,
                coefficients: vec![poly(0, 1)],
            }],
            vec![],
            poly(0, 7),
        )
        .unwrap();
        let commitment = CommitmentConstraint::new(
            &layout,
            &key,
            1,
            vec![super::super::commitments::CommitmentTerm {
                key_offset: 0,
                witness_offset: 0,
                witness_count: 1,
                scalar: 1,
            }],
            vec![],
            vec![poly(0, 14)],
        )
        .unwrap();
        let set = RingConstraintSet::new(&layout, vec![sparse], vec![commitment]).unwrap();
        assert_eq!(set.challenge_count(), 2);
        let aggregate = set.aggregate(&[poly(0, 3), poly(1, 5)]).unwrap();
        assert!(set.check(&[poly(0, 7)]).unwrap());
        assert!(aggregate.check(&[poly(0, 7)]).unwrap());
        let residual = aggregate.evaluate(&[poly(0, 8)]).unwrap();
        assert_eq!(
            residual.reference_bitpack(),
            poly(0, 3).add(&poly(1, 10)).reference_bitpack()
        );
        assert!(matches!(
            set.aggregate(&[poly(0, 3)]),
            Err(ConstraintError::Length)
        ));
    }

    #[test]
    fn almost_uniform_transcript_schedule_matches_reference_seed_transition() {
        let mut transcript = ReferenceTranscript::from_state([29; 32]);
        let mut reference = ReferenceTranscript::from_state([29; 32]);
        let seed = reference.derive_reference_seed();
        let expected =
            super::super::super::commitment::reference_almost_uniform(&seed, 0, 33).unwrap();
        let actual = transcript.almost_uniform_challenges(33).unwrap();
        assert_eq!(transcript.state(), reference.state());
        for (a, b) in actual.iter().zip(expected) {
            assert_eq!(a.reference_bitpack(), b.reference_bitpack());
        }
        let initial = transcript.state();
        assert!(transcript.almost_uniform_challenges(usize::MAX).is_err());
        assert_eq!(transcript.state(), initial);
        assert!(transcript.almost_uniform_challenges(0).unwrap().is_empty());
        assert_ne!(transcript.state(), initial);
    }

    #[test]
    fn set_construction_checks_domains_layouts_and_empty_witnesses() {
        let layout = WitnessLayout::new(&[1]).unwrap();
        let scalar = SparseConstraint::new(
            &layout,
            EquationDomain::ConstantCoefficient,
            vec![],
            vec![],
            zero(),
        )
        .unwrap();
        assert!(matches!(
            RingConstraintSet::new(&layout, vec![scalar], vec![]),
            Err(ConstraintError::Domain)
        ));
        let integer = IntegerSlotConstraint::new(&WitnessLayout::new(&[2]).unwrap(), 0, 1).unwrap();
        assert!(matches!(
            ScalarConstraintSet::new(&layout, vec![], vec![], vec![integer]),
            Err(ConstraintError::Layout)
        ));
        let set = ScalarConstraintSet::new(&layout, vec![], vec![], vec![]).unwrap();
        assert!(matches!(set.check(&[]), Err(ConstraintError::Length)));
        assert!(set.aggregate(&[], &[]).unwrap().check(&[zero()]).unwrap());
    }
}
