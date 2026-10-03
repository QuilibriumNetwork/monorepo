//! Complete prover-side submission boundary. This has no native proof backend.
//! Witness callbacks carry secrets: implementations must not log them or use
//! this stream as transaction serialization. A verifier must independently
//! reconstruct the statement and parameters, never accept these from a prover.
use super::*;
use ring_lift::{binary_lift::Variable, LiftError};
use zeroize::Zeroizing;

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmissionCounts {
    pub original_binary_polynomials: usize,
    pub auxiliary_binary_polynomials: usize,
    /// Approximate-norm witness polynomials, indexed after every binary one.
    pub short_polynomials: usize,
    pub scalar_equations: usize,
    pub linear_equations: usize,
    pub selection_equations: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SubmissionError<E> {
    Scalar(ScalarPlanError),
    Lift(LiftError),
    InvalidBinary,
    IndexOverflow,
    Sink(E),
}

/// The sink is a trusted prover adapter, not a verifier interface. Every
/// `binary` call MUST create an exact binary domain, not a norm upper bound.
/// On any error, discard all partial state; `finish` is never called on error.
/// Handles are global and contiguous; auxiliary handles cannot alias originals
/// or auxiliary variables allocated for previous lifting equations.
pub trait RelationSink {
    type Error;
    /// `short_normsq[k]` is the squared l2 bound of short polynomial `k`,
    /// whose global index is `original + auxiliary + k`.
    fn begin(
        &mut self,
        modulus: i128,
        degree: usize,
        counts: SubmissionCounts,
        short_normsq: &[u64],
    ) -> Result<(), Self::Error>;
    fn binary(&mut self, index: usize, private_coefficients: &[u8]) -> Result<(), Self::Error>;
    /// Short witness coefficients (signed integers within the declared bound).
    fn short(&mut self, index: usize, private_coefficients: &[i64]) -> Result<(), Self::Error>;
    fn scalar(&mut self, row: ScalarRow<'_>) -> Result<(), Self::Error>;
    fn linear(&mut self, terms: &[(Vec<i64>, usize)], rhs: &[i64]) -> Result<(), Self::Error>;
    /// Emit s*one - s*zero + zero - selected = 0 over the backend ring.
    /// Scalar rows in the same submission enforce that s is a scalar.
    fn selection(&mut self, row: SelectionRow) -> Result<(), Self::Error>;
    fn finish(&mut self, counts: SubmissionCounts) -> Result<(), Self::Error>;
}

/// Public equations and exact binary domains only. There is no witness callback.
/// A verifier must construct the circuit from its own public transaction inputs;
/// it must not accept circuit coefficients or dimensions supplied with a proof.
pub trait StatementSink {
    type Error;
    fn begin(
        &mut self,
        modulus: i128,
        degree: usize,
        counts: SubmissionCounts,
        short_normsq: &[u64],
    ) -> Result<(), Self::Error>;
    fn binary_domain(&mut self, index: usize) -> Result<(), Self::Error>;
    fn short_domain(&mut self, index: usize) -> Result<(), Self::Error>;
    fn scalar(&mut self, row: ScalarRow<'_>) -> Result<(), Self::Error>;
    fn linear(&mut self, terms: &[(Vec<i64>, usize)], rhs: &[i64]) -> Result<(), Self::Error>;
    fn selection(&mut self, row: SelectionRow) -> Result<(), Self::Error>;
    fn finish(&mut self, counts: SubmissionCounts) -> Result<(), Self::Error>;
}

impl CompiledAmountRelation {
    /// Emit the compiled graph without reading its private assignment. This
    /// boundary also works after witness buffers have been erased. A network
    /// verifier must construct the public-input circuit independently.
    pub fn submit_public_statement<S: StatementSink>(
        &self,
        sink: &mut S,
    ) -> Result<SubmissionCounts, SubmissionError<S::Error>> {
        let expected = self
            .backend_submission_counts()
            .map_err(|error| match error {
                SubmissionError::Scalar(e) => SubmissionError::Scalar(e),
                SubmissionError::Lift(e) => SubmissionError::Lift(e),
                SubmissionError::InvalidBinary => SubmissionError::InvalidBinary,
                SubmissionError::IndexOverflow => SubmissionError::IndexOverflow,
                SubmissionError::Sink(e) => match e {},
            })?;
        let normsq = self.short_normsq();
        sink.begin(PROOF_MODULUS, Poly::D, expected, &normsq)
            .map_err(SubmissionError::Sink)?;
        // Declare every witness before any row: originals, lifting
        // auxiliaries, then short polynomials, in one global index space.
        let plans = self
            .ring_backend_plans()
            .map(|plan| plan.map(|p| p.public_statement()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(SubmissionError::Lift)?;
        for index in 0..self.binary.len() {
            sink.binary_domain(index).map_err(SubmissionError::Sink)?;
        }
        let mut next = self.binary.len();
        let mut bases = Vec::with_capacity(plans.len());
        for statement in &plans {
            let base = next;
            bases.push(base);
            next = next
                .checked_add(statement.auxiliary_polynomials())
                .ok_or(SubmissionError::IndexOverflow)?;
            for index in base..next {
                sink.binary_domain(index).map_err(SubmissionError::Sink)?;
            }
        }
        let auxiliary = next - self.binary.len();
        for k in 0..self.short_count() {
            sink.short_domain(next + k).map_err(SubmissionError::Sink)?;
        }
        for row in self
            .scalar_backend_plan()
            .map_err(SubmissionError::Scalar)?
            .rows()
        {
            sink.scalar(row).map_err(SubmissionError::Sink)?;
        }
        for row in &self.exact_ring {
            let (terms, rhs) = row.emitted();
            let terms: Vec<_> = terms.into_iter().map(|(c, i)| (c, self.resolve(i, auxiliary))).collect();
            sink.linear(&terms, &rhs).map_err(SubmissionError::Sink)?;
        }
        for (statement, base) in plans.iter().zip(&bases) {
            for row in statement.rows() {
                let terms: Vec<_> = row
                    .terms
                    .iter()
                    .map(|(coefficient, index)| {
                        let index = match index {
                            Variable::Original(i) => self.resolve(*i, auxiliary),
                            Variable::Auxiliary(i) => base + i,
                        };
                        (coefficient.clone(), index)
                    })
                    .collect();
                sink.linear(&terms, &row.rhs)
                    .map_err(SubmissionError::Sink)?;
            }
        }
        for row in self.native_membership_rows() {
            let terms: Vec<_> = row.terms.into_iter().map(|(c, i)| (c, self.resolve(i, auxiliary))).collect();
            sink.linear(&terms, &row.rhs).map_err(SubmissionError::Sink)?;
        }
        debug_assert_eq!(
            next,
            expected.original_binary_polynomials + expected.auxiliary_binary_polynomials
        );
        for row in self.selection_backend_rows() {
            sink.selection(self.resolve_selection(row, auxiliary)).map_err(SubmissionError::Sink)?;
        }
        sink.finish(expected).map_err(SubmissionError::Sink)?;
        Ok(expected)
    }

    fn resolve_selection(&self, row: SelectionRow, auxiliary: usize) -> SelectionRow {
        SelectionRow {
            selector: self.resolve(row.selector, auxiliary),
            terms: row
                .terms
                .iter()
                .map(|&(w, z, o, s)| (w, self.resolve(z, auxiliary), self.resolve(o, auxiliary), self.resolve(s, auxiliary)))
                .collect(),
        }
    }

    /// Public-only allocation pass for native frontends that require witness
    /// and constraint counts at construction. Does not read witness values.
    pub fn backend_submission_counts(
        &self,
    ) -> Result<SubmissionCounts, SubmissionError<core::convert::Infallible>> {
        self.scalar_backend_plan()
            .map_err(SubmissionError::Scalar)?;
        for row in &self.exact_ring {
            row.checked_interval(self.binary.len()).map_err(SubmissionError::Lift)?;
        }
        let mut counts = SubmissionCounts {
            original_binary_polynomials: self.binary.len(),
            short_polynomials: self.short_count(),
            scalar_equations: self.scalar.len(),
            linear_equations: self.exact_ring.len(),
            selection_equations: self.selection_backend_rows().count(),
            ..Default::default()
        };
        for plan in self.ring_backend_plans() {
            let plan = plan.map_err(SubmissionError::Lift)?;
            let (rows, auxiliary) = if plan.direct_residual_bound().is_some() {
                (1, 0)
            } else {
                (
                    plan.plane_count(),
                    plan.quotient_bits() as usize
                        + (plan.plane_count() - 1) * plan.carry_bits() as usize,
                )
            };
            counts.linear_equations = counts
                .linear_equations
                .checked_add(rows)
                .ok_or(SubmissionError::IndexOverflow)?;
            counts.auxiliary_binary_polynomials = counts
                .auxiliary_binary_polynomials
                .checked_add(auxiliary)
                .ok_or(SubmissionError::IndexOverflow)?;
        }
        counts.linear_equations = counts
            .linear_equations
            .checked_add(self.native_membership_row_count())
            .ok_or(SubmissionError::IndexOverflow)?;
        counts
            .original_binary_polynomials
            .checked_add(counts.auxiliary_binary_polynomials)
            .and_then(|n| n.checked_add(counts.short_polynomials))
            .ok_or(SubmissionError::IndexOverflow)?;
        Ok(counts)
    }

    /// Submit every relation family together, with one global binary-variable
    /// namespace. This does not produce a proof.
    pub fn submit_private_relation<S: RelationSink>(
        &self,
        sink: &mut S,
    ) -> Result<SubmissionCounts, SubmissionError<S::Error>> {
        let scalar = self
            .scalar_backend_plan()
            .map_err(SubmissionError::Scalar)?;
        if self
            .binary
            .iter()
            .any(|p| p.c.len() != Poly::D || p.c.iter().any(|&v| v > 1))
        {
            return Err(SubmissionError::InvalidBinary);
        }
        let expected = self
            .backend_submission_counts()
            .map_err(|error| match error {
                SubmissionError::Scalar(e) => SubmissionError::Scalar(e),
                SubmissionError::Lift(e) => SubmissionError::Lift(e),
                SubmissionError::InvalidBinary => SubmissionError::InvalidBinary,
                SubmissionError::IndexOverflow => SubmissionError::IndexOverflow,
                SubmissionError::Sink(e) => match e {},
            })?;
        let normsq = self.short_normsq();
        sink.begin(PROOF_MODULUS, Poly::D, expected, &normsq)
            .map_err(SubmissionError::Sink)?;
        let mut counts = SubmissionCounts {
            original_binary_polynomials: self.binary.len(),
            short_polynomials: self.short_count(),
            ..Default::default()
        };
        let encoded = self
            .ring_backend_plans()
            .map(|plan| plan.and_then(|p| p.encode_relation(self)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(SubmissionError::Lift)?;
        for (index, p) in self.binary.iter().enumerate() {
            let coefficients = Zeroizing::new(p.c.iter().map(|&v| v as u8).collect::<Vec<_>>());
            sink.binary(index, &coefficients)
                .map_err(SubmissionError::Sink)?;
        }
        let mut next = self.binary.len();
        let mut bases = Vec::with_capacity(encoded.len());
        for lift in &encoded {
            let base = next;
            bases.push(base);
            next = next
                .checked_add(lift.auxiliary_polynomials())
                .ok_or(SubmissionError::IndexOverflow)?;
            lift.visit_private_auxiliary(|index, coefficients| {
                    sink.binary(base + index, coefficients)
                })
                .map_err(SubmissionError::Sink)?;
        }
        let auxiliary = next - self.binary.len();
        counts.auxiliary_binary_polynomials = auxiliary;
        for (k, p) in self.short.iter().enumerate() {
            let coefficients = Zeroizing::new(p.c.iter().map(|&v| v as i64).collect::<Vec<_>>());
            sink.short(next + k, &coefficients).map_err(SubmissionError::Sink)?;
        }
        for row in scalar.rows() {
            sink.scalar(row).map_err(SubmissionError::Sink)?;
            counts.scalar_equations += 1;
        }
        for row in &self.exact_ring {
            let (terms, rhs) = row.emitted();
            let terms: Vec<_> = terms.into_iter().map(|(c, i)| (c, self.resolve(i, auxiliary))).collect();
            sink.linear(&terms, &rhs).map_err(SubmissionError::Sink)?;
            counts.linear_equations += 1;
        }
        for (lift, base) in encoded.iter().zip(&bases) {
            for row in lift.rows() {
                let terms: Vec<_> = row
                    .terms
                    .iter()
                    .map(|(coefficient, index)| {
                        let index = match index {
                            Variable::Original(i) => self.resolve(*i, auxiliary),
                            Variable::Auxiliary(i) => base + i,
                        };
                        (coefficient.clone(), index)
                    })
                    .collect();
                sink.linear(&terms, &row.rhs)
                    .map_err(SubmissionError::Sink)?;
                counts.linear_equations += 1;
            }
        }
        for row in self.native_membership_rows() {
            let terms: Vec<_> = row.terms.into_iter().map(|(c, i)| (c, self.resolve(i, auxiliary))).collect();
            sink.linear(&terms, &row.rhs).map_err(SubmissionError::Sink)?;
            counts.linear_equations += 1;
        }
        for row in self.selection_backend_rows() {
            sink.selection(self.resolve_selection(row, auxiliary)).map_err(SubmissionError::Sink)?;
            counts.selection_equations += 1;
        }
        assert_eq!(
            counts, expected,
            "public backend allocation plan disagrees with submission"
        );
        sink.finish(counts).map_err(SubmissionError::Sink)?;
        Ok(counts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::{Digest, Sha3_256};

    #[derive(Default)]
    struct Sink {
        next: usize,
        scalar: usize,
        linear: usize,
        selections: usize,
        finished: bool,
        fail_at: Option<usize>,
        public_digest: Sha3_256,
    }
    impl RelationSink for Sink {
        type Error = &'static str;
        fn begin(
            &mut self,
            p: i128,
            d: usize,
            counts: SubmissionCounts,
            short_normsq: &[u64],
        ) -> Result<(), Self::Error> {
            assert_eq!((p, d), (PROOF_MODULUS, Poly::D));
            assert!(counts.original_binary_polynomials > 0);
            assert_eq!(short_normsq.len(), counts.short_polynomials);
            for n in short_normsq { Digest::update(&mut self.public_digest, n.to_le_bytes()); }
            Digest::update(&mut self.public_digest, p.to_le_bytes());
            Digest::update(&mut self.public_digest, (d as u64).to_le_bytes());
            Ok(())
        }
        fn short(&mut self, index: usize, coefficients: &[i64]) -> Result<(), Self::Error> {
            if index != self.next || coefficients.len() != Poly::D { return Err("short order"); }
            Digest::update(&mut self.public_digest, b"short");
            Digest::update(&mut self.public_digest, (index as u64).to_le_bytes());
            self.next += 1;
            Ok(())
        }
        fn binary(&mut self, index: usize, coefficients: &[u8]) -> Result<(), Self::Error> {
            if self.fail_at == Some(index) {
                return Err("injected sink failure");
            }
            assert_eq!(index, self.next);
            assert_eq!(coefficients.len(), Poly::D);
            assert!(coefficients.iter().all(|&v| v <= 1));
            self.next += 1;
            Digest::update(&mut self.public_digest, [0]);
            Digest::update(&mut self.public_digest, (index as u64).to_le_bytes());
            Ok(())
        }
        fn scalar(&mut self, row: ScalarRow<'_>) -> Result<(), Self::Error> {
            assert!(row
                .terms
                .iter()
                .all(|&(_, p, c)| p < self.next && c < Poly::D));
            self.scalar += 1;
            Digest::update(&mut self.public_digest, [1]);
            Digest::update(&mut self.public_digest, row.rhs.to_le_bytes());
            Digest::update(
                &mut self.public_digest,
                (row.terms.len() as u64).to_le_bytes(),
            );
            for &(a, p, c) in row.terms {
                Digest::update(&mut self.public_digest, a.to_le_bytes());
                Digest::update(&mut self.public_digest, (p as u64).to_le_bytes());
                Digest::update(&mut self.public_digest, (c as u64).to_le_bytes());
            }
            Ok(())
        }
        fn linear(&mut self, terms: &[(Vec<i64>, usize)], rhs: &[i64]) -> Result<(), Self::Error> {
            assert!(terms
                .iter()
                .all(|(p, i)| p.len() == Poly::D && *i < self.next));
            assert_eq!(rhs.len(), Poly::D);
            self.linear += 1;
            Digest::update(&mut self.public_digest, [2]);
            Digest::update(&mut self.public_digest, (terms.len() as u64).to_le_bytes());
            for (p, i) in terms {
                Digest::update(&mut self.public_digest, (*i as u64).to_le_bytes());
                for v in p {
                    Digest::update(&mut self.public_digest, v.to_le_bytes());
                }
            }
            for v in rhs {
                Digest::update(&mut self.public_digest, v.to_le_bytes());
            }
            Ok(())
        }
        fn selection(&mut self, row: SelectionRow) -> Result<(), Self::Error> {
            assert!(row.handles().all(|i| i < self.next));
            self.selections += 1;
            Digest::update(&mut self.public_digest, [3]);
            Digest::update(&mut self.public_digest, (row.selector as u64).to_le_bytes());
            for (w, z, o, s) in &row.terms {
                Digest::update(&mut self.public_digest, w.to_le_bytes());
                for i in [z, o, s] { Digest::update(&mut self.public_digest, (*i as u64).to_le_bytes()); }
            }
            Ok(())
        }
        fn finish(&mut self, counts: SubmissionCounts) -> Result<(), Self::Error> {
            assert_eq!(
                self.next,
                counts.original_binary_polynomials + counts.auxiliary_binary_polynomials + counts.short_polynomials
            );
            assert_eq!(
                (self.scalar, self.linear),
                (counts.scalar_equations, counts.linear_equations)
            );
            self.finished = true;
            assert_eq!(self.selections, counts.selection_equations);
            Ok(())
        }
    }

    impl StatementSink for Sink {
        type Error = &'static str;
        fn begin(&mut self, p: i128, d: usize, c: SubmissionCounts, n: &[u64]) -> Result<(), Self::Error> {
            RelationSink::begin(self, p, d, c, n)
        }
        fn binary_domain(&mut self, index: usize) -> Result<(), Self::Error> {
            // Test collector records only the domain, never assignment values.
            RelationSink::binary(self, index, &[0; Poly::D])
        }
        fn short_domain(&mut self, index: usize) -> Result<(), Self::Error> {
            RelationSink::short(self, index, &[0; Poly::D])
        }
        fn scalar(&mut self, row: ScalarRow<'_>) -> Result<(), Self::Error> {
            RelationSink::scalar(self, row)
        }
        fn linear(&mut self, terms: &[(Vec<i64>, usize)], rhs: &[i64]) -> Result<(), Self::Error> {
            RelationSink::linear(self, terms, rhs)
        }
        fn selection(&mut self, row: SelectionRow) -> Result<(), Self::Error> {
            RelationSink::selection(self, row)
        }
        fn finish(&mut self, c: SubmissionCounts) -> Result<(), Self::Error> {
            RelationSink::finish(self, c)
        }
    }

    #[test]
    fn membership_submission_includes_hashes_and_whole_node_selectors() {
        use membership::{
            InputPath, MembershipKey, MembershipStatement, NoteSecrets, RecipientSecret,
        };
        let context = [61; 32];
        let amount_key = CommitmentKey::derive(&context);
        let membership_key = MembershipKey::derive(&context);
        let note = NoteSecrets::from_seeds(
            &context,
            &RecipientSecret::from_seed(&context, &[99; 32]),
            &[62; 32],
        );
        let commitment = amount_key.commit(7, &note.opening);
        let coins = [(7, &note.opening, &commitment)];
        let leaf = membership_key.leaf(&membership_key.owner_key(&note.owner), &commitment);
        let root = membership_key.parent(&leaf, &leaf);
        let images = [membership_key.key_image(&note.owner)];
        let siblings = [leaf];
        let statement = MembershipStatement {
            root: &root,
            key_images: &images,
            depth: 1,
        };
        let paths = [InputPath {
            owner: &note.owner,
            siblings: &siblings,
            right: &[false],
        }];
        let mut relation = CompiledAmountRelation::compile_with_membership(
            &amount_key,
            &membership_key,
            &coins,
            &coins,
            0,
            0,
            &statement,
            &paths,
        )
        .unwrap()
        .with_transaction_context(b"canonical transaction fixture");
        let mut sink = Sink::default();
        let counts = relation.submit_private_relation(&mut sink).unwrap();
        assert!(sink.finished);
        assert_eq!(
            counts.selection_equations,
            relation.membership_shape().quadratic_selection_equations
        );
        // One unit-weight quadratic selection per limb of each node row.
        assert_eq!(counts.selection_equations, membership::NODE_RANK * 6);
        // Ownership is now three linear identity rows per input; no Boolean
        // hash circuits remain, so the scalar statement is small.
        assert!(counts.scalar_equations < 1_000);
        assert!(relation.membership_shape().hash_ring_equations >= 3 * membership::IDENTITY_RANK + 2 * membership::NODE_RANK);
        let mut portable = super::super::portable::PortableWitnessChecker::default();
        assert_eq!(
            relation.submit_private_relation(&mut portable).unwrap(),
            counts
        );
        assert!(
            counts.linear_equations
                > relation.shape().ring_equations + relation.membership_shape().hash_ring_equations
        );
        // The public route must preserve every equation after private buffers
        // are gone, including ownership, membership and lifting auxiliaries.
        for p in &mut relation.binary {
            p.c.zeroize();
            p.c.clear();
        }
        let mut public = Sink::default();
        assert_eq!(
            relation.submit_public_statement(&mut public).unwrap(),
            counts
        );
        assert!(public.finished);
        let expected_digest = sink.public_digest.finalize();
        assert_eq!(public.public_digest.finalize(), expected_digest);
        let rebuilt = PublicAmountRelation::compile_with_membership(
            &amount_key,
            &membership_key,
            &[commitment.clone()],
            0,
            0,
            &statement,
        )
        .unwrap()
        .with_transaction_context(b"canonical transaction fixture");
        assert!(rebuilt.relation.binary.iter().all(|p| p.c.is_empty()));
        let mut independent = Sink::default();
        assert_eq!(rebuilt.submit(&mut independent).unwrap(), counts);
        assert_eq!(independent.public_digest.finalize(), expected_digest);
        // A changed memo/recipient/operation byte must alter the proof statement
        // even when amounts, roots and key images are unchanged.
        let altered_context = PublicAmountRelation::compile_with_membership(
            &amount_key,
            &membership_key,
            &[commitment.clone()],
            0,
            0,
            &statement,
        )
        .unwrap()
        .with_transaction_context(b"canonical transaction fixturf");
        let mut capture = Sink::default();
        assert_eq!(altered_context.submit(&mut capture).unwrap(), counts);
        assert_ne!(capture.public_digest.finalize(), expected_digest);
        // Public inputs must change the equations without a matching assignment.
        for (changed_output, inflow, outflow, changed_root, changed_images) in [
            (
                amount_key.commit(8, &note.opening),
                0,
                0,
                root.clone(),
                images.clone(),
            ),
            (commitment.clone(), 1, 0, root.clone(), images.clone()),
            (commitment.clone(), 0, 1, root.clone(), images.clone()),
            (
                commitment.clone(),
                0,
                0,
                membership::Node::zero(),
                images.clone(),
            ),
            (
                commitment.clone(),
                0,
                0,
                root.clone(),
                [membership::Node::from_identity_bytes(&[9; membership::IDENTITY_BYTES]).unwrap()],
            ),
        ] {
            let altered = PublicAmountRelation::compile_with_membership(
                &amount_key,
                &membership_key,
                &[changed_output],
                inflow,
                outflow,
                &MembershipStatement {
                    root: &changed_root,
                    key_images: &changed_images,
                    depth: 1,
                },
            )
            .unwrap()
            .with_transaction_context(b"canonical transaction fixture");
            let mut capture = Sink::default();
            assert_eq!(altered.submit(&mut capture).unwrap(), counts);
            assert_ne!(capture.public_digest.finalize(), expected_digest);
        }
        assert!(matches!(
            relation.submit_private_relation(&mut Sink::default()),
            Err(SubmissionError::InvalidBinary)
        ));
        let mut failing = Sink {
            fail_at: Some(relation.binary.len() + 1),
            ..Default::default()
        };
        assert!(matches!(
            relation.submit_public_statement(&mut failing),
            Err(SubmissionError::Sink("injected sink failure"))
        ));
        assert!(!failing.finished);
    }

    #[test]
    fn exact_canonical_rows_preserve_domains_and_public_private_submission() {
        let mut relation = CompiledAmountRelation {
            binary: Vec::new(), short: Vec::new(), short_bound: Vec::new(), ring: Vec::new(), exact_ring: Vec::new(),
            scalar: Vec::new(), input_commitment_planes: Vec::new(),
            membership: membership::MembershipConstraints::default(),
        };
        let values = Poly { c: (0..Poly::D).map(|i| {
            if i % 2 == 0 { i as u64 } else { Poly::Q - 1 - i as u64 }
        }).collect() };
        let handles = relation.canonical_residue(&values);
        assert!(relation.validate_local_witness());
        let mut private = Sink::default();
        let counts = relation.submit_private_relation(&mut private).unwrap();
        assert_eq!(counts.original_binary_polynomials, 72);
        assert_eq!(counts.auxiliary_binary_polynomials, 0);
        assert_eq!(counts.linear_equations, 1);
        let mut checker = super::super::portable::PortableWitnessChecker::default();
        relation.submit_private_relation(&mut checker).unwrap();

        // Independent p-ring checker must reject an application-modulus alias.
        for (bit, &index) in handles.iter().enumerate() {
            relation.binary[index].c[0] = (Poly::Q >> bit) & 1;
        }
        assert!(!relation.validate_local_witness());
        let mut checker = super::super::portable::PortableWitnessChecker::default();
        assert!(relation.submit_private_relation(&mut checker).is_err());

        // Public emission requires no assignment, and preserves exact i64 coefficients.
        for p in &mut relation.binary { p.c.clear(); }
        let mut public = Sink::default();
        assert_eq!(relation.submit_public_statement(&mut public).unwrap(), counts);
        assert_eq!(private.public_digest.finalize(), public.public_digest.finalize());

        relation.exact_ring[0].terms[0].0 = PROOF_MODULUS as i64;
        assert!(matches!(relation.backend_submission_counts(), Err(SubmissionError::Lift(LiftError::ResidualMayWrap))));
        relation.exact_ring[0].terms[0] = (1, relation.binary.len());
        assert!(matches!(relation.backend_submission_counts(), Err(SubmissionError::Lift(LiftError::InvalidShape))));
    }

    #[test]
    fn submission_allocates_global_handles_and_propagates_sink_failure() {
        let context = [51; 32];
        let key = CommitmentKey::derive(&context);
        let opening = AmountOpening::from_seed(&context, &[52; 32]);
        let commitment = key.commit(257, &opening);
        let coin = [(257, &opening, &commitment)];
        let relation = CompiledAmountRelation::compile(&key, &coin, &coin, 0, 0).unwrap();
        let mut sink = Sink::default();
        let counts = relation.submit_private_relation(&mut sink).unwrap();
        assert!(sink.finished && counts.auxiliary_binary_polynomials > 0);
        assert_eq!(counts.scalar_equations, relation.shape().scalar_equations);
        assert_eq!(
            counts.linear_equations,
            // Eighteen lifted rows each expand to two equations under QPF4.
            relation.shape().ring_equations + 18
        );
        let mut failing = Sink {
            fail_at: Some(relation.binary.len() + 1),
            ..Default::default()
        };
        assert!(matches!(
            relation.submit_private_relation(&mut failing),
            Err(SubmissionError::Sink("injected sink failure"))
        ));
        assert!(!failing.finished);
    }
}
