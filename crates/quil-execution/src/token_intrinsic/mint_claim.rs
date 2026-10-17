//! Consumption adapter for a globally authorized mint, available only through
//! an explicitly configured token engine.
//! The caller must serialize staging/commit and own the entire application.
use super::mint_authorization;
use crate::domains;
use quil_lattice_ct::confidential::mint_claim::MintClaim;
use quil_types::{
    error::{QuilError, Result},
    execution::FrameExecutionContext,
    store::ClockStore,
};

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("mint claim: {message}"))
}

pub struct VerifiedMintClaim {
    claim: MintClaim,
}

/// The root must come from the cited canonical global frame, bounded by the
/// enclosing consensus frame. This never reads or debits global reward state.
pub fn verify_from_clock(
    clock: &dyn ClockStore,
    context: FrameExecutionContext,
    network: &[u8; 32],
    application: &[u8; 32],
    bytes: &[u8],
    max_outputs: usize,
) -> Result<VerifiedMintClaim> {
    let bound = context.finalized_global_frame.ok_or_else(|| {
        QuilError::ExecutionUnavailable("mint claim requires consensus global anchor".into())
    })?;
    let claim = MintClaim::decode(bytes, network, application)
        .map_err(|_| invalid("invalid encoding or context"))?;
    if application != &domains::QUIL_TOKEN || claim.outputs.len() > max_outputs {
        return Err(invalid("unsupported application or dimensions"));
    }
    let root = super::mint::clock_reward_root(clock, claim.cited_global_frame, bound)?;
    if root != claim.global_root {
        return Err(invalid("global root mismatch"));
    }
    mint_authorization::verify_membership(
        network,
        application,
        &claim.receipt,
        &claim.outputs,
        claim.fee,
        &root,
        &claim.forest_proof,
    )?;
    Ok(VerifiedMintClaim { claim })
}

impl VerifiedMintClaim {
}
