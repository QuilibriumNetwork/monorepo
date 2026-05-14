//! Compute intrinsic materialization — record state changes in the
//! HypergraphState for CodeDeploy, CodeExecute, and CodeFinalize.
//!
//! Mirrors Go's compute materialize behaviour: the deployment, the
//! request layout (rendezvous + DAG + stages + per-op metadata), and
//! the finalization state transitions are written to the hypergraph.
//! Circuit execution itself stays off-chain — same as Go (which only
//! records the request layout in materialize and lets external
//! executors consume it).

use quil_types::crypto::{BulletproofProver, KeyManager};
use quil_types::error::{QuilError, Result};
use quil_types::execution::CircuitCompiler;

use crate::compute_intrinsic::intrinsic::{
    code_deployment_address, verify_code_deployment, verify_code_execute,
    verify_code_finalize,
};
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

/// Materialize a CodeDeploy: build a code-storage tree whose only entry
/// is `Circuit` at index `[0<<2]`, then write its serialized form at
/// `poseidon(domain || circuit)`.
///
/// Mirrors Go `CodeDeployment.Materialize` at
/// `compute_intrinsic_code_deployment.go:131-191`. The stored value is
/// the serialized indexed tree, NOT the canonical-bytes
/// `CodeDeployment` envelope.
pub fn materialize_code_deploy(
    state: &HypergraphState,
    deployment: &CodeDeployment,
    frame_number: u64,
) -> Result<[u8; 32]> {
    use num_bigint::BigInt;

    let addr = code_deployment_address(&deployment.domain, &deployment.circuit)?;
    let va_disc = vertex_adds_discriminator()?;

    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(
        &[0u8 << 2],
        &deployment.circuit,
        &[],
        &BigInt::from(deployment.circuit.len() as u64),
    )?;

    let blob = quil_tries::serialize_go_tree(tree.root.as_ref())?;
    state.set(
        &deployment.domain,
        &addr,
        &va_disc,
        frame_number,
        blob,
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
/// Mirrors Go `CodeExecute.Materialize` at
/// `compute_intrinsic_code_execute.go:225-316`. Builds the execution
/// DAG and writes the structured tree:
///
/// - index 0: rendezvous (32 bytes)
/// - index 1: serialized DAG (op→deps map)
/// - index 2: serialized stages (topological levels)
/// - indices 3+: per-operation metadata (Application + identifier +
///   stage + read/write sets — read/write sets are empty for
///   intrinsic contexts, matching Go's `TODO(2.2)` behaviour)
///
/// The vertex address is `poseidon(domain || rendezvous)` and the
/// value written to `state.set` is the serialized indexed tree (the
/// raw blob bytes, ready for downstream tree reads). Actual circuit
/// execution stays off-chain — same as Go.
pub fn materialize_code_execute(
    state: &HypergraphState,
    execute: &CodeExecute,
    frame_number: u64,
) -> Result<[u8; 32]> {
    use super::intrinsic::{build_execution_dag, ExecutionDagValidated};
    use super::ops::{Application, ExecuteOperation};
    use num_bigint::BigInt;

    // Allow empty operation lists — Go's CodeExecute.Materialize
    // validates non-empty earlier (in Verify) but the materialize
    // helper itself is tolerant. We mirror that with an empty DAG.
    let dag = if execute.execute_operations.is_empty() {
        ExecutionDagValidated::default()
    } else {
        build_execution_dag(&execute.execute_operations)?
    };

    let mut tree = quil_tries::VectorCommitmentTree::new();

    // index 0: rendezvous
    tree.insert(
        &[0u8 << 2],
        &execute.rendezvous,
        &[],
        &BigInt::from(execute.rendezvous.len() as u64),
    )?;

    // index 1: serialized DAG (operations + per-op dependencies)
    let dag_bytes = serialize_dag(&dag);
    tree.insert(
        &[1u8 << 2],
        &dag_bytes,
        &[],
        &BigInt::from(dag_bytes.len() as u64),
    )?;

    // index 2: serialized stages
    let stages_bytes = serialize_stages(&dag);
    tree.insert(
        &[2u8 << 2],
        &stages_bytes,
        &[],
        &BigInt::from(stages_bytes.len() as u64),
    )?;

    // indices 3+: per-operation metadata
    for (i, raw_op) in execute.execute_operations.iter().enumerate() {
        let op = ExecuteOperation::from_canonical_bytes(raw_op)?;
        let app = Application::from_canonical_bytes(&op.application)?;
        let stage = *dag.op_stage.get(&op.identifier).unwrap_or(&0u32);
        let op_bytes = serialize_operation(&app, &op.identifier, stage);
        let key = [(((i + 3) as u8) << 2) as u8];
        tree.insert(
            &key,
            &op_bytes,
            &[],
            &BigInt::from(op_bytes.len() as u64),
        )?;
    }

    let blob = quil_tries::serialize_go_tree(tree.root.as_ref())?;
    // Go uses the rendezvous directly as the vertex address
    // (`compute_intrinsic_code_execute.go:307-313`), NOT
    // `poseidon(domain || rendezvous)`.
    let addr = execute.rendezvous;
    let va_disc = vertex_adds_discriminator()?;
    state.set(
        &execute.domain,
        &addr,
        &va_disc,
        frame_number,
        blob,
    )?;
    Ok(addr)
}

/// Encode a `u32` length-prefixed bytes block.
fn write_lp(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Mirror of Go `CodeExecute.serializeDAG` (compute_intrinsic_code_execute.go:764).
/// Layout: u32 op_count || per-op (u32 id_len || id || u32 deps_count
/// || per-dep (u32 dep_id_len || dep_id)). The Rust DAG validator
/// doesn't track per-op Dependencies (intrinsic-context access sets
/// are empty per Go `TODO(2.2)`), so deps_count is always 0.
fn serialize_dag(dag: &super::intrinsic::ExecutionDagValidated) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(dag.operations.len() as u32).to_be_bytes());
    for id in &dag.operations {
        write_lp(&mut buf, id);
        buf.extend_from_slice(&0u32.to_be_bytes()); // dependencies count = 0
    }
    buf
}

/// Mirror of Go `CodeExecute.serializeStages` (compute_intrinsic_code_execute.go:815).
fn serialize_stages(dag: &super::intrinsic::ExecutionDagValidated) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(dag.stages.len() as u32).to_be_bytes());
    for stage in &dag.stages {
        buf.extend_from_slice(&(stage.len() as u32).to_be_bytes());
        for id in stage {
            write_lp(&mut buf, id);
        }
    }
    buf
}

/// Mirror of Go `CodeExecute.serializeOperation` (compute_intrinsic_code_execute.go:856).
/// Layout: u32 addr_len || addr || u8 exec_ctx || u32 id_len || id ||
/// u32 stage || u32 read_set_count || ... || u32 write_set_count ...
/// Read/write sets are always empty for intrinsic contexts.
fn serialize_operation(
    app: &super::ops::Application,
    identifier: &[u8],
    stage: u32,
) -> Vec<u8> {
    let mut buf = Vec::new();
    write_lp(&mut buf, &app.address);
    buf.push(app.execution_context as u8);
    write_lp(&mut buf, identifier);
    buf.extend_from_slice(&stage.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // read_set count
    buf.extend_from_slice(&0u32.to_be_bytes()); // write_set count
    buf
}

// =====================================================================
// CodeFinalize materialization
// =====================================================================

/// Compute the results-vertex address for a CodeFinalize:
/// `poseidon(rendezvous || "RESULTS_CODE_FINALIZE")`.
pub fn results_address(rendezvous: &[u8; 32]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(32 + 21);
    preimage.extend_from_slice(rendezvous);
    preimage.extend_from_slice(b"RESULTS_CODE_FINALIZE");
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

/// Compute the state-changes-vertex address for a CodeFinalize:
/// `poseidon(rendezvous || "STATE_CHANGES_CODE_FINALIZE")`.
pub fn state_changes_address(rendezvous: &[u8; 32]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(32 + 27);
    preimage.extend_from_slice(rendezvous);
    preimage.extend_from_slice(b"STATE_CHANGES_CODE_FINALIZE");
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

/// Serialize CodeFinalize results in the Go binary format. Mirrors
/// `compute_intrinsic_code_finalize.go:392-435`.
fn serialize_finalize_results(results: &[Vec<u8>]) -> Result<Vec<u8>> {
    use crate::compute_intrinsic::ops::ExecutionResult;
    let mut buf = Vec::new();
    buf.extend_from_slice(&(results.len() as u32).to_be_bytes());
    for raw in results {
        let r = ExecutionResult::from_canonical_bytes(raw)?;
        buf.extend_from_slice(&(r.operation_id.len() as u32).to_be_bytes());
        buf.extend_from_slice(&r.operation_id);
        buf.push(if r.success { 1 } else { 0 });
        buf.extend_from_slice(&(r.output.len() as u32).to_be_bytes());
        buf.extend_from_slice(&r.output);
    }
    Ok(buf)
}

/// Serialize CodeFinalize state-change summary (domain || addr_lp ||
/// poseidon(new_value)). Mirrors
/// `compute_intrinsic_code_finalize.go:438-475`.
fn serialize_finalize_state_changes(changes: &[Vec<u8>]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&(changes.len() as u32).to_be_bytes());
    for raw in changes {
        let t = StateTransition::from_canonical_bytes(raw)?;
        buf.extend_from_slice(&t.domain);
        buf.extend_from_slice(&(t.address.len() as u32).to_be_bytes());
        buf.extend_from_slice(&t.address);
        let h = quil_crypto::poseidon::hash_bytes_to_32(&t.new_value)?;
        buf.extend_from_slice(&h);
    }
    Ok(buf)
}

/// Materialize a CodeFinalize. Mirrors Go `CodeFinalize.Materialize` at
/// `compute_intrinsic_code_finalize.go:118-280`. Two distinct vertices
/// are written:
///
/// 1. **Results vertex** at `poseidon(rendezvous || "RESULTS_CODE_FINALIZE")`:
///    a tree with index 0 = rendezvous (32 bytes), index 1 = serialized
///    results, index 2 = serialized state-change summary.
/// 2. **State-changes vertex** at
///    `poseidon(rendezvous || "STATE_CHANGES_CODE_FINALIZE")`: a tree
///    keyed by uint16 BE index, value = canonical-bytes
///    StateTransition.
pub fn materialize_code_finalize(
    state: &HypergraphState,
    finalize: &CodeFinalize,
    domain: &[u8; 32],
    frame_number: u64,
) -> Result<()> {
    use num_bigint::BigInt;
    let va_disc = vertex_adds_discriminator()?;

    // 1. Build and write the state-changes vertex (must run before
    //    results, so the results-tree state-change summary references
    //    the same data we wrote).
    let mut changes_tree = quil_tries::VectorCommitmentTree::new();
    for (i, raw) in finalize.state_changes.iter().enumerate() {
        let key = (i as u16).to_be_bytes();
        changes_tree.insert(&key, raw, &[], &BigInt::from(raw.len() as u64))?;
    }
    let changes_blob = quil_tries::serialize_go_tree(changes_tree.root.as_ref())?;
    let changes_addr = state_changes_address(&finalize.rendezvous)?;
    state.set(domain, &changes_addr, &va_disc, frame_number, changes_blob)?;

    // 2. Build and write the results vertex.
    let mut results_tree = quil_tries::VectorCommitmentTree::new();
    // Index 0: rendezvous
    results_tree.insert(
        &[0u8 << 2],
        &finalize.rendezvous,
        &[],
        &BigInt::from(32),
    )?;
    // Index 1: serialized results
    let results_bytes = serialize_finalize_results(&finalize.results)?;
    results_tree.insert(
        &[1u8 << 2],
        &results_bytes,
        &[],
        &BigInt::from(results_bytes.len() as u64),
    )?;
    // Index 2: serialized state-change summary
    let state_changes_bytes =
        serialize_finalize_state_changes(&finalize.state_changes)?;
    results_tree.insert(
        &[2u8 << 2],
        &state_changes_bytes,
        &[],
        &BigInt::from(state_changes_bytes.len() as u64),
    )?;

    let results_blob = quil_tries::serialize_go_tree(results_tree.root.as_ref())?;
    let results_addr = results_address(&finalize.rendezvous)?;
    state.set(domain, &results_addr, &va_disc, frame_number, results_blob)?;

    Ok(())
}

// =====================================================================
// Verify-gated dispatch wrappers
// =====================================================================
//
// Callers that process incoming compute ops should invoke these
// wrappers so verify runs BEFORE any state mutation. Matches the Go
// engine pattern where `IntrinsicOperation.Verify` is called before
// `Materialize`.

/// Verify and then materialize a CodeDeployment. Wraps
/// `verify_code_deployment` + `materialize_code_deploy`. Returns the
/// deploy address on success.
pub fn materialize_code_deploy_verified(
    state: &HypergraphState,
    deployment: &CodeDeployment,
    frame_number: u64,
    compiler: &dyn CircuitCompiler,
) -> Result<[u8; 32]> {
    verify_code_deployment(compiler, &deployment.circuit)?;
    materialize_code_deploy(state, deployment, frame_number)
}

/// Verify and then materialize a CodeExecute.
pub fn materialize_code_execute_verified(
    state: &HypergraphState,
    execute: &CodeExecute,
    frame_number: u64,
    bp: &dyn BulletproofProver,
) -> Result<[u8; 32]> {
    verify_code_execute(execute, bp)?;
    materialize_code_execute(state, execute, frame_number)
}

/// Verify and then materialize a CodeFinalize. The `domain` parameter
/// doubles as the compute-application domain used in the signature
/// context.
pub fn materialize_code_finalize_verified(
    state: &HypergraphState,
    finalize: &CodeFinalize,
    domain: &[u8; 32],
    write_public_key: &[u8],
    frame_number: u64,
    key_manager: &dyn KeyManager,
) -> Result<()> {
    verify_code_finalize(finalize, domain, write_public_key, key_manager)?;
    materialize_code_finalize(state, finalize, domain, frame_number)
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use quil_hypergraph::testing::{MemStore, StubProver};

    fn stub_state() -> HypergraphState {
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(MemStore::new()),
            Arc::new(StubProver),
        ));
        HypergraphState::new(crdt)
    }

    // -- CodeDeploy tests ----------------------------------------------

    #[test]
    fn deploy_stores_circuit_in_tree_at_index_zero() {
        let state = stub_state();
        let deployment = CodeDeployment {
            circuit: vec![0xAAu8; 100],
            input_types: vec![b"uint64".to_vec()],
            output_types: vec![b"bool".to_vec()],
            domain: [0x11u8; 32],
        };
        let addr = materialize_code_deploy(&state, &deployment, 1).unwrap();
        assert_eq!(addr.len(), 32);
        let va_disc = vertex_adds_discriminator().unwrap();
        let stored = state.get(&deployment.domain, &addr, &va_disc).unwrap();
        let blob = stored.expect("deploy must write a vertex");
        // Stored value is a serialized indexed tree containing the
        // circuit at index 0<<2, NOT raw CodeDeployment canonical bytes.
        let root = quil_tries::deserialize_go_tree(&blob).unwrap();
        let tree = quil_tries::VectorCommitmentTree { root };
        assert_eq!(tree.get(&[0u8 << 2]).unwrap(), &deployment.circuit[..]);
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
        // Go uses rendezvous directly as the vertex address.
        assert_eq!(addr, execute.rendezvous);
        let va_disc = vertex_adds_discriminator().unwrap();
        let stored = state.get(&execute.domain, &addr, &va_disc).unwrap();
        assert!(stored.is_some());
        // The materialize blob is the serialized indexed tree (Go-format).
        // Deserialize and confirm slot 0 holds the rendezvous.
        let root = quil_tries::deserialize_go_tree(&stored.unwrap()).unwrap();
        let tree = quil_tries::VectorCommitmentTree { root };
        let rendezvous_back = tree.get(&[0u8 << 2]).unwrap();
        assert_eq!(rendezvous_back, &execute.rendezvous);
    }

    #[test]
    fn execute_address_is_rendezvous() {
        let state = stub_state();
        let execute = CodeExecute {
            domain: [0x66u8; 32],
            rendezvous: [0x77u8; 32],
            ..Default::default()
        };
        let a1 = materialize_code_execute(&state, &execute, 1).unwrap();
        let a2 = materialize_code_execute(&state, &execute, 2).unwrap();
        assert_eq!(a1, a2);
        assert_eq!(a1, execute.rendezvous);
    }

    // -- CodeFinalize tests --------------------------------------------

    #[test]
    fn finalize_writes_two_vertices_results_and_state_changes() {
        let state = stub_state();
        let domain = [0x88u8; 32];
        let transition = StateTransition {
            domain,
            address: vec![0xCCu8; 32],
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

        let va_disc = vertex_adds_discriminator().unwrap();

        // Results vertex
        let res_addr = results_address(&finalize.rendezvous).unwrap();
        let res_blob = state.get(&domain, &res_addr, &va_disc).unwrap();
        let res_blob = res_blob.expect("results vertex must exist");
        let root = quil_tries::deserialize_go_tree(&res_blob).unwrap();
        let res_tree = quil_tries::VectorCommitmentTree { root };
        // Index 0 == rendezvous
        assert_eq!(res_tree.get(&[0u8 << 2]).unwrap(), &finalize.rendezvous[..]);
        // Index 1 starts with u32 BE count = 0 (no results)
        assert_eq!(&res_tree.get(&[1u8 << 2]).unwrap()[..4], &0u32.to_be_bytes()[..]);
        // Index 2 starts with u32 BE count = 1 state change
        assert_eq!(&res_tree.get(&[2u8 << 2]).unwrap()[..4], &1u32.to_be_bytes()[..]);

        // State changes vertex
        let changes_addr = state_changes_address(&finalize.rendezvous).unwrap();
        let changes_blob = state.get(&domain, &changes_addr, &va_disc).unwrap();
        let changes_blob = changes_blob.expect("state-changes vertex must exist");
        let croot = quil_tries::deserialize_go_tree(&changes_blob).unwrap();
        let ctree = quil_tries::VectorCommitmentTree { root: croot };
        // Index uint16 BE 0 holds the canonical-bytes StateTransition
        let stored_change = ctree.get(&0u16.to_be_bytes()).unwrap();
        let round_tripped =
            StateTransition::from_canonical_bytes(stored_change).unwrap();
        assert_eq!(round_tripped, transition);
    }

    #[test]
    fn finalize_results_address_differs_from_state_changes_address() {
        let rdv = [0xAAu8; 32];
        let r = results_address(&rdv).unwrap();
        let s = state_changes_address(&rdv).unwrap();
        assert_ne!(r, s);
    }

    #[test]
    fn finalize_empty_writes_both_vertices() {
        let state = stub_state();
        let domain = [0xDDu8; 32];
        let finalize = CodeFinalize {
            rendezvous: [0xEEu8; 32],
            ..Default::default()
        };
        materialize_code_finalize(&state, &finalize, &domain, 1).unwrap();
        // Two vertices: results + state-changes.
        assert!(state.changeset_len() >= 2);
        let va_disc = vertex_adds_discriminator().unwrap();
        let r = results_address(&finalize.rendezvous).unwrap();
        let s = state_changes_address(&finalize.rendezvous).unwrap();
        assert!(state.get(&domain, &r, &va_disc).unwrap().is_some());
        assert!(state.get(&domain, &s, &va_disc).unwrap().is_some());
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
