//! Compute intrinsic materialization stubs -- record state changes in
//! the HypergraphState for CodeDeploy, CodeExecute, and CodeFinalize.
//!
//! These do not actually run circuit code; they record the deployment,
//! execution request, and finalization state transitions so the
//! hypergraph reflects the compute operations. Actual QCL/Ferret
//! execution is deferred to a future integration.

use quil_types::error::Result;

use crate::compute_intrinsic::intrinsic::code_deployment_address;
use crate::compute_intrinsic::ops::{
    CodeDeployment, CodeExecute, CodeFinalize, StateTransition,
};
use crate::hypergraph_state::{vertex_adds_discriminator, HypergraphState};

// =====================================================================
// State key prefixes for compute vertices
// =====================================================================

/// Compute the execution request address from domain + rendezvous.
/// `poseidon(domain || rendezvous)` -> 32 bytes.
pub fn execution_request_address(
    domain: &[u8; 32],
    rendezvous: &[u8; 32],
) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(rendezvous);
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

// =====================================================================
// CodeDeploy materialization
// =====================================================================

/// Materialize a CodeDeploy: store the circuit code bytes in the
/// hypergraph state under the deploy address derived from
/// `poseidon(domain || circuit)`.
///
/// The stored value is the full `CodeDeployment` canonical bytes so
/// that subsequent CodeExecute operations can look up the circuit,
/// input types, and output types.
pub fn materialize_code_deploy(
    state: &HypergraphState,
    deployment: &CodeDeployment,
    frame_number: u64,
) -> Result<[u8; 32]> {
    let addr = code_deployment_address(&deployment.domain, &deployment.circuit)?;
    let va_disc = vertex_adds_discriminator()?;
    let value = deployment.to_canonical_bytes()?;
    state.set(
        &deployment.domain,
        &addr,
        &va_disc,
        frame_number,
        value,
    )?;
    Ok(addr)
}

// =====================================================================
// CodeExecute materialization
// =====================================================================

/// Materialize a CodeExecute: record the execution request (domain,
/// rendezvous, operations) in the hypergraph state. The address is
/// derived from `poseidon(domain || rendezvous)`.
///
/// Actual execution is deferred -- this only records that the request
/// exists so that a future CodeFinalize can reference it.
pub fn materialize_code_execute(
    state: &HypergraphState,
    execute: &CodeExecute,
    frame_number: u64,
) -> Result<[u8; 32]> {
    let addr = execution_request_address(&execute.domain, &execute.rendezvous)?;
    let va_disc = vertex_adds_discriminator()?;
    let value = execute.to_canonical_bytes()?;
    state.set(
        &execute.domain,
        &addr,
        &va_disc,
        frame_number,
        value,
    )?;
    Ok(addr)
}

// =====================================================================
// CodeFinalize materialization
// =====================================================================

/// Materialize a CodeFinalize: apply each state transition by writing
/// the new value under `poseidon(domain || address)`, then mark the
/// execution as complete by overwriting the rendezvous vertex with
/// the finalization data (results + proof).
pub fn materialize_code_finalize(
    state: &HypergraphState,
    finalize: &CodeFinalize,
    domain: &[u8; 32],
    frame_number: u64,
) -> Result<()> {
    let va_disc = vertex_adds_discriminator()?;

    // Apply each state transition -- write new_value at the
    // transition's address within its domain.
    for raw in &finalize.state_changes {
        let transition = StateTransition::from_canonical_bytes(raw)?;
        let transition_addr =
            quil_crypto::poseidon::hash_bytes_to_32(&transition.address)?;
        state.set(
            &transition.domain,
            &transition_addr,
            &va_disc,
            frame_number,
            transition.new_value.clone(),
        )?;
    }

    // Mark the execution as finalized by storing the CodeFinalize
    // data at the rendezvous address.
    let rendezvous_addr =
        execution_request_address(domain, &finalize.rendezvous)?;
    let value = finalize.to_canonical_bytes()?;
    state.set(domain, &rendezvous_addr, &va_disc, frame_number, value)?;

    Ok(())
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use quil_types::crypto::NoopInclusionProver;
    use quil_hypergraph::testing::MemStore;

    fn stub_state() -> HypergraphState {
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(NoopInclusionProver),
        ));
        HypergraphState::new(crdt)
    }

    // -- CodeDeploy tests ----------------------------------------------

    #[test]
    fn deploy_stores_code_and_returns_address() {
        let state = stub_state();
        let deployment = CodeDeployment {
            circuit: vec![0xAAu8; 100],
            input_types: vec![b"uint64".to_vec()],
            output_types: vec![b"bool".to_vec()],
            domain: [0x11u8; 32],
        };
        let addr = materialize_code_deploy(&state, &deployment, 1).unwrap();
        assert_eq!(addr.len(), 32);
        // Verify we can read back the stored value
        let va_disc = vertex_adds_discriminator().unwrap();
        let stored = state.get(&deployment.domain, &addr, &va_disc).unwrap();
        assert!(stored.is_some());
        let round_tripped =
            CodeDeployment::from_canonical_bytes(&stored.unwrap()).unwrap();
        assert_eq!(round_tripped, deployment);
    }

    #[test]
    fn deploy_address_is_deterministic() {
        let state = stub_state();
        let deployment = CodeDeployment {
            circuit: vec![0xBBu8; 50],
            input_types: vec![],
            output_types: vec![],
            domain: [0x22u8; 32],
        };
        let a1 = materialize_code_deploy(&state, &deployment, 1).unwrap();
        let a2 = materialize_code_deploy(&state, &deployment, 2).unwrap();
        assert_eq!(a1, a2);
    }

    #[test]
    fn deploy_different_circuits_get_different_addresses() {
        let state = stub_state();
        let d1 = CodeDeployment {
            circuit: vec![0x01u8; 50],
            domain: [0x33u8; 32],
            ..Default::default()
        };
        let d2 = CodeDeployment {
            circuit: vec![0x02u8; 50],
            domain: [0x33u8; 32],
            ..Default::default()
        };
        let a1 = materialize_code_deploy(&state, &d1, 1).unwrap();
        let a2 = materialize_code_deploy(&state, &d2, 1).unwrap();
        assert_ne!(a1, a2);
    }

    // -- CodeExecute tests ---------------------------------------------

    #[test]
    fn execute_stores_request_and_returns_address() {
        let state = stub_state();
        let execute = CodeExecute {
            proof_of_payment: vec![vec![0x00, 100]],
            domain: [0x44u8; 32],
            rendezvous: [0x55u8; 32],
            execute_operations: vec![],
        };
        let addr = materialize_code_execute(&state, &execute, 10).unwrap();
        assert_eq!(addr.len(), 32);
        let va_disc = vertex_adds_discriminator().unwrap();
        let stored = state.get(&execute.domain, &addr, &va_disc).unwrap();
        assert!(stored.is_some());
        let round_tripped =
            CodeExecute::from_canonical_bytes(&stored.unwrap()).unwrap();
        assert_eq!(round_tripped, execute);
    }

    #[test]
    fn execute_address_is_deterministic() {
        let state = stub_state();
        let execute = CodeExecute {
            domain: [0x66u8; 32],
            rendezvous: [0x77u8; 32],
            ..Default::default()
        };
        let a1 = materialize_code_execute(&state, &execute, 1).unwrap();
        let a2 = materialize_code_execute(&state, &execute, 2).unwrap();
        assert_eq!(a1, a2);
    }

    // -- CodeFinalize tests --------------------------------------------

    #[test]
    fn finalize_applies_state_transitions() {
        let state = stub_state();
        let domain = [0x88u8; 32];
        let transition_addr = vec![0xCCu8; 32];
        let transition = StateTransition {
            domain,
            address: transition_addr.clone(),
            old_value: b"old".to_vec(),
            new_value: b"new".to_vec(),
            proof: vec![],
        };
        let finalize = CodeFinalize {
            rendezvous: [0x99u8; 32],
            results: vec![],
            state_changes: vec![transition.to_canonical_bytes().unwrap()],
            proof_of_execution: vec![0xFFu8; 64],
            message_output: vec![],
        };
        materialize_code_finalize(&state, &finalize, &domain, 20).unwrap();

        // The transition's new_value should be stored
        let va_disc = vertex_adds_discriminator().unwrap();
        let transition_hash =
            quil_crypto::poseidon::hash_bytes_to_32(&transition_addr).unwrap();
        let stored = state.get(&domain, &transition_hash, &va_disc).unwrap();
        assert_eq!(stored, Some(b"new".to_vec()));
    }

    #[test]
    fn finalize_stores_finalization_at_rendezvous() {
        let state = stub_state();
        let domain = [0xAAu8; 32];
        let finalize = CodeFinalize {
            rendezvous: [0xBBu8; 32],
            results: vec![],
            state_changes: vec![],
            proof_of_execution: vec![0xEEu8; 64],
            message_output: vec![],
        };
        materialize_code_finalize(&state, &finalize, &domain, 30).unwrap();

        let va_disc = vertex_adds_discriminator().unwrap();
        let rendezvous_addr =
            execution_request_address(&domain, &finalize.rendezvous).unwrap();
        let stored = state.get(&domain, &rendezvous_addr, &va_disc).unwrap();
        assert!(stored.is_some());
        let round_tripped =
            CodeFinalize::from_canonical_bytes(&stored.unwrap()).unwrap();
        assert_eq!(round_tripped, finalize);
    }

    #[test]
    fn finalize_empty_is_ok() {
        let state = stub_state();
        let domain = [0xDDu8; 32];
        let finalize = CodeFinalize {
            rendezvous: [0xEEu8; 32],
            ..Default::default()
        };
        // No state transitions, no results -- should still succeed
        materialize_code_finalize(&state, &finalize, &domain, 1).unwrap();
        assert!(state.changeset_len() > 0);
    }

    // -- Address helper tests ------------------------------------------

    #[test]
    fn execution_request_address_is_deterministic() {
        let a1 = execution_request_address(&[0x11u8; 32], &[0x22u8; 32]).unwrap();
        let a2 = execution_request_address(&[0x11u8; 32], &[0x22u8; 32]).unwrap();
        assert_eq!(a1, a2);
    }

    #[test]
    fn execution_request_address_differs_by_rendezvous() {
        let a1 = execution_request_address(&[0x11u8; 32], &[0x22u8; 32]).unwrap();
        let a2 = execution_request_address(&[0x11u8; 32], &[0x33u8; 32]).unwrap();
        assert_ne!(a1, a2);
    }
}
