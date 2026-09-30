//! Amount conservation for explicitly identified source commitments, such as
//! an escrow claim. Source commitments are public; amounts/openings are private.
//! This does not prove spend authority, eligibility, expiry or non-replay.
use super::*;

fn dimensions(inputs: usize, outputs: usize) -> Result<(), TokenError> {
    if inputs == 0 || outputs == 0 { return Err(TokenError::Length); }
    if inputs.saturating_add(outputs) > MAX_PRIVATE_COINS {
        return Err(TokenError::TooManyCoins);
    }
    Ok(())
}

impl PublicAmountRelation {
    /// Reconstruct opening/range/conservation equations against the exact
    /// public input and output commitments. No public inflow is allowed.
    /// The enclosing operation must authenticate each source, authorize its
    /// consumption, enforce replay/expiry, and bind its canonical context.
    pub fn compile_public_spend(
        key: &CommitmentKey,
        inputs: &[AmountCommitment],
        outputs: &[AmountCommitment],
        outflow: u128,
    ) -> Result<Self, TokenError> {
        dimensions(inputs.len(), outputs.len())?;
        let opening = AmountOpening { r: std::array::from_fn(|_| Poly::zero()) };
        let input_coins: Vec<_> = inputs.iter().map(|c| (0, &opening, c)).collect();
        let output_coins: Vec<_> = outputs.iter().map(|c| (0, &opening, c)).collect();
        let mut relation = CompiledAmountRelation::compile_graph_inner(
            key, &input_coins, &output_coins, 0, outflow,
            &BalanceTrace { carries: [0; 17] }, false,
        );
        relation.erase_private();
        Ok(Self { relation })
    }
}

impl CompiledAmountRelation {
    /// Prover counterpart to `PublicAmountRelation::compile_public_spend`.
    /// Knowledge of openings is not authorization to spend the source.
    pub fn compile_public_spend(
        key: &CommitmentKey,
        inputs: &[(u128, &AmountOpening, &AmountCommitment)],
        outputs: &[(u128, &AmountOpening, &AmountCommitment)],
        outflow: u128,
    ) -> Result<Self, TokenError> {
        dimensions(inputs.len(), outputs.len())?;
        let trace = check_amount_witness(key, inputs, outputs, 0, outflow)?;
        Ok(Self::compile_graph_inner(key, inputs, outputs, 0, outflow, &trace, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "native-proof")]
    #[test]
    #[ignore = "native public-commitment spend proof; run via Taskfile"]
    fn native_public_spend_roundtrip() {
        use backend::native::{self, NativeBudget};
        let context = [63; 32];
        let key = CommitmentKey::derive(&context);
        let openings: [_; 3] = std::array::from_fn(|i| AmountOpening::from_seed(&context, &[i as u8; 32]));
        let amounts = [u128::MAX, u128::MAX - 258, 256];
        let commitments: [_; 3] = std::array::from_fn(|i| key.commit(amounts[i], &openings[i]));
        let coins: [_; 3] = std::array::from_fn(|i| (amounts[i], &openings[i], &commitments[i]));
        let tx_context = b"public commitment spend fixture; not an authorized escrow claim";
        let private = CompiledAmountRelation::compile_public_spend(&key, &coins[..1], &coins[1..], 2)
            .unwrap().with_transaction_context(tx_context);
        let budget = NativeBudget { max_native_bytes: 1 << 30 };
        let started = std::time::Instant::now();
        let proof = native::prove(&private, budget).unwrap();
        drop(private);
        let public = PublicAmountRelation::compile_public_spend(&key, &commitments[..1], &commitments[1..], 2)
            .unwrap().with_transaction_context(tx_context);
        assert!(native::verify_owned(public, &proof, budget).unwrap());
        let changed_source = [key.commit(amounts[0] - 1, &openings[0])];
        let public = PublicAmountRelation::compile_public_spend(&key, &changed_source, &commitments[1..], 2)
            .unwrap().with_transaction_context(tx_context);
        assert!(!native::verify_owned(public, &proof, budget).unwrap());
        let public = PublicAmountRelation::compile_public_spend(&key, &commitments[..1], &commitments[1..], 2)
            .unwrap().with_transaction_context(b"different claim policy or destination");
        assert!(!native::verify_owned(public, &proof, budget).unwrap());
        // This measures the amount proof alone, not a complete claim payload.
        assert!(proof.len() < 256 << 10);
        eprintln!("native_public_spend sources=1 outputs=2 changed_source_rejected=true changed_context_rejected=true proof_bytes={} seconds={:.3}",
            proof.len(), started.elapsed().as_secs_f64());
    }

    #[test]
    fn public_spend_binds_sources_outputs_and_conservation() {
        let context = [63; 32];
        let key = CommitmentKey::derive(&context);
        let openings: [_; 3] = std::array::from_fn(|i| AmountOpening::from_seed(&context, &[i as u8; 32]));
        let amounts = [u128::MAX, u128::MAX - 258, 256];
        let commitments: [_; 3] = std::array::from_fn(|i| key.commit(amounts[i], &openings[i]));
        let coins: [_; 3] = std::array::from_fn(|i| (amounts[i], &openings[i], &commitments[i]));
        let private = CompiledAmountRelation::compile_public_spend(&key, &coins[..1], &coins[1..], 2)
            .unwrap().with_transaction_context(b"escrow claim fixture; authority checked externally");
        let public = PublicAmountRelation::compile_public_spend(&key, &commitments[..1], &commitments[1..], 2)
            .unwrap().with_transaction_context(b"escrow claim fixture; authority checked externally");
        assert!(private.validate_local_witness());
        assert!(private.input_commitment_planes.is_empty());
        assert!(private.ring == public.relation.ring);
        assert!(private.scalar == public.relation.scalar);
        assert!(private.membership == public.relation.membership);
        assert_eq!(private.binary.len(), public.relation.binary.len());
        assert!(public.relation.binary.iter().all(|p| p.c.is_empty()));

        // Test the actual constraints with the original witness, rather than
        // relying only on constructor-side checks of a changed source/output.
        for index in 0..3 {
            let mut changed = commitments.clone();
            changed[index] = key.commit(amounts[index] - 1, &openings[index]);
            let mut relation = PublicAmountRelation::compile_public_spend(&key, &changed[..1], &changed[1..], 2)
                .unwrap().with_transaction_context(b"escrow claim fixture; authority checked externally").relation;
            relation.binary = private.binary.clone();
            assert!(!relation.validate_local_witness());
        }
        assert!(matches!(CompiledAmountRelation::compile_public_spend(&key, &coins[..1], &coins[1..], 1), Err(TokenError::Unbalanced)));
        let wrong_opening = [(amounts[0], &openings[1], &commitments[0])];
        assert!(matches!(CompiledAmountRelation::compile_public_spend(&key, &wrong_opening, &coins[1..], 2), Err(TokenError::OpeningMismatch)));
        assert!(matches!(PublicAmountRelation::compile_public_spend(&key, &[], &commitments[1..], 0), Err(TokenError::Length)));
        assert!(matches!(PublicAmountRelation::compile_public_spend(&key, &commitments[..1], &[], 0), Err(TokenError::Length)));
        assert!(matches!(PublicAmountRelation::compile_public_spend(&key, &vec![commitments[0].clone(); MAX_PRIVATE_COINS], &commitments[1..], 0), Err(TokenError::TooManyCoins)));
    }
}
