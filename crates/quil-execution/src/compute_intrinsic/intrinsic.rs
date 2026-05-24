//! Compute intrinsic operations: CodeDeployment, CodeExecute,
//! CodeFinalize verify + materialize.

use std::collections::{HashMap, HashSet};

use num_bigint::BigInt;
use quil_types::crypto::{BulletproofProver, KeyManager, KeyType};
use quil_types::error::{QuilError, Result};
use quil_types::execution::CircuitCompiler;

use super::ops::{
    Application, CodeExecute, CodeFinalize, ExecuteOperation,
};

// =====================================================================
// CodeDeployment
// =====================================================================

/// Verify a code deployment by validating the compiled circuit.
///
/// Go equivalent: `CodeDeployment.Verify`
/// (`compute_intrinsic_code_deployment.go:120-128`). The Go version
/// only runs `compiler.ValidateCircuit` — no signature check — so this
/// function mirrors that exactly.
pub fn verify_code_deployment(
    compiler: &dyn CircuitCompiler,
    circuit: &[u8],
) -> Result<bool> {
    compiler.validate_circuit(circuit)?;
    Ok(true)
}

/// Get the cost of a code deployment (proportional to circuit size).
pub fn code_deployment_cost(circuit: &[u8]) -> BigInt {
    BigInt::from(circuit.len() as i64)
}

/// Compute the address for a deployed code vertex.
/// `poseidon(domain || circuit)` → 32 bytes.
pub fn code_deployment_address(domain: &[u8], circuit: &[u8]) -> Result<[u8; 32]> {
    let mut preimage = Vec::with_capacity(domain.len() + circuit.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(circuit);
    quil_crypto::poseidon::hash_bytes_to_32(&preimage)
}

/// Create a code vertex tree storing the compiled circuit.
pub fn create_code_vertex_tree(
    circuit: &[u8],
) -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    tree.insert(&[0x00], circuit, &[], &BigInt::from(circuit.len() as i64))
        .map_err(|e| QuilError::Internal(format!("code tree: {}", e)))?;
    Ok(tree)
}

// =====================================================================
// CodeExecute
// =====================================================================

/// Get the cost of a code execution (based on operation count).
pub fn code_execute_cost(execute_operations: &[Vec<u8>]) -> BigInt {
    // Cost proportional to number of operations × average operation size
    let total_bytes: usize = execute_operations.iter().map(|op| op.len()).sum();
    BigInt::from(total_bytes as i64)
}

/// Domain tag string appended to the per-app domain when signing a
/// `CodeFinalize`. Matches Go's literal at
/// `compute_intrinsic_code_finalize.go:378`.
pub const CODE_FINALIZE_DOMAIN_TAG: &[u8] = b"CODE_FINALIZE";

/// Build the Ed448 `sign_with_domain` context bytes for a CodeFinalize
/// signature: `compute_app_domain || "CODE_FINALIZE"`.
///
/// This is the raw byte concatenation Go uses (NOT poseidon-wrapped —
/// see `ed448_key.go:74-80` where `SignWithDomain` prepends `domain`
/// to the message before calling `ed448.Sign`). The task description
/// mentioned poseidon as a possibility; inspection of the Go reference
/// confirms it is a plain byte concatenation.
pub fn code_finalize_domain(compute_app_domain: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + CODE_FINALIZE_DOMAIN_TAG.len());
    out.extend_from_slice(compute_app_domain);
    out.extend_from_slice(CODE_FINALIZE_DOMAIN_TAG);
    out
}

/// Canonical-bytes signing message for CodeFinalize: the full
/// canonical encoding of the finalize struct with
/// `proof_of_execution` zeroed out. Mirrors
/// `compute_intrinsic_code_finalize.go:366-371`.
pub fn code_finalize_signing_message(f: &CodeFinalize) -> Result<Vec<u8>> {
    let mut clone = f.clone();
    clone.proof_of_execution.clear();
    clone.to_canonical_bytes()
}

/// Verify a `CodeFinalize` intrinsic operation.
///
/// Mirrors `CodeFinalize.Verify`
/// (`compute_intrinsic_code_finalize.go:347-390`):
///
/// 1. Require at least one execution result.
/// 2. Every `StateTransition` must have 32-byte domain and address.
/// 3. Re-serialize the finalize with `proof_of_execution = nil` as the
///    signed message.
/// 4. Domain is raw bytes `compute_app_domain || "CODE_FINALIZE"`.
/// 5. Validate the Ed448 signature stored in `proof_of_execution` via
///    the `KeyManager`.
///
/// Arguments:
/// - `finalize`: the decoded CodeFinalize op.
/// - `compute_app_domain`: the 32-byte compute-application domain
///   (the `domain` field on Go's `CodeFinalize`; not a proto field,
///   it's carried in the message envelope).
/// - `write_public_key`: the Ed448 write key from the deployed
///   `ComputeConfiguration` for that application.
/// - `key_manager`: signature validator.
pub fn verify_code_finalize(
    finalize: &CodeFinalize,
    compute_app_domain: &[u8; 32],
    write_public_key: &[u8],
    key_manager: &dyn KeyManager,
) -> Result<bool> {
    // 1. Must have at least one result.
    if finalize.results.is_empty() {
        return Err(QuilError::InvalidArgument(
            "verify: invalid code finalize: no execution results provided"
                .into(),
        ));
    }

    // 2. State-change domain + address length checks. Each
    //    `state_changes` entry is a nested StateTransition canonical
    //    blob; decode and confirm the field widths match.
    //
    //    Also enforce that every state change targets THIS compute
    //    app's domain. A verified finalize that claims writes into
    //    other domains (token, global, hypergraph, or some other
    //    compute app) would let a compute-domain owner mutate state
    //    outside their own scope. Materialization implicitly routes
    //    by destination domain, so the practical blast radius is
    //    small today; this check keeps the verify contract explicit
    //    so a future materialize refactor can't widen it.
    for (i, sc_bytes) in finalize.state_changes.iter().enumerate() {
        let sc = super::ops::StateTransition::from_canonical_bytes(sc_bytes)
            .map_err(|e| {
                QuilError::InvalidArgument(format!(
                    "verify: invalid code finalize: decoding state \
                     change {}: {}",
                    i, e
                ))
            })?;
        if sc.domain.len() != 32 {
            return Err(QuilError::InvalidArgument(
                "verify: invalid code finalize: invalid domain length in \
                 state change"
                    .into(),
            ));
        }
        if sc.address.len() != 32 {
            return Err(QuilError::InvalidArgument(
                "verify: invalid code finalize: invalid address length in \
                 state change"
                    .into(),
            ));
        }
        if sc.domain.as_slice() != compute_app_domain.as_slice() {
            return Err(QuilError::InvalidArgument(format!(
                "verify: invalid code finalize: state change {} targets \
                 domain {} which differs from compute app domain {}",
                i,
                hex::encode(&sc.domain),
                hex::encode(compute_app_domain),
            )));
        }
    }

    // 3. Rebuild the signed message.
    let msg = code_finalize_signing_message(finalize)?;

    // 4 / 5. Verify Ed448 signature with `domain || CODE_FINALIZE`.
    let domain_ctx = code_finalize_domain(compute_app_domain);
    let valid = key_manager.validate_signature(
        KeyType::Ed448,
        write_public_key,
        &msg,
        &finalize.proof_of_execution,
        &domain_ctx,
    )?;
    if !valid {
        return Err(QuilError::InvalidArgument(
            "verify: invalid code finalize: invalid signature".into(),
        ));
    }
    Ok(true)
}

// =====================================================================
// CodeExecute
// =====================================================================

/// `ExecutionContext` values mirrored from Go
/// (`compute_intrinsic_code_execute.go:23-29`).
pub const EXECUTION_CONTEXT_INTRINSIC: u32 = 0;
pub const EXECUTION_CONTEXT_HYPERGRAPH: u32 = 1;
pub const EXECUTION_CONTEXT_EXTRINSIC: u32 = 2;

/// Maximum number of operations in a single CodeExecute request.
/// Mirror of `MaxOperationsLimit` in Go
/// (`compute_intrinsic_code_execute.go:21`).
pub const MAX_OPERATIONS_LIMIT: usize = 100;

/// 56-byte zero DECAF448 scalar indicating "no alt-fee payer". Go
/// compares against `make([]byte, 56)`; DECAF448 public keys are 56
/// bytes.
fn is_zero_payer(pk: &[u8]) -> bool {
    pk.len() == 56 && pk.iter().all(|&b| b == 0)
}

/// Verify the payment proof carried in `proof_of_payment[0..2]`.
///
/// Mirror of `CodeExecute.Verify`
/// (`compute_intrinsic_code_execute.go:350-370`):
///
/// - `proof_of_payment[0]` is the payer's DECAF448 public key (56
///   bytes). If it is all-zeros the alt-fee path is skipped and only
///   DAG validation runs (matches the Go `Prove` sentinel).
/// - `proof_of_payment[1]` is a DECAF448 Schnorr "simple" signature
///   over the `rendezvous`.
/// - DAG validation must succeed.
pub fn verify_code_execute(
    execute: &CodeExecute,
    bp: &dyn BulletproofProver,
) -> Result<bool> {
    // Payment proof check.
    let payer = execute.proof_of_payment.first().map(Vec::as_slice).unwrap_or(&[]);
    if !payer.is_empty() && !is_zero_payer(payer) {
        // When a real payer is present, proof_of_payment[1] must be
        // present and must verify against `rendezvous`.
        let sig = execute.proof_of_payment.get(1).ok_or_else(|| {
            QuilError::InvalidArgument(
                "verify: invalid code execute: missing proof_of_payment \
                 signature"
                    .into(),
            )
        })?;
        if !bp.simple_verify(&execute.rendezvous, sig, payer) {
            return Err(QuilError::InvalidArgument(
                "verify: invalid code execute: invalid signature".into(),
            ));
        }
    }

    // DAG validation.
    let _dag = build_execution_dag(&execute.execute_operations)?;

    Ok(true)
}

// =====================================================================
// CodeExecute DAG validation
// =====================================================================

/// A validated DAG — stages are operation identifiers grouped into
/// levels where every op in level N depends only on ops in levels
/// 0..N. Mirror of Go's `ExecutionDAG`
/// (`compute_intrinsic_code_execute.go:49-53`).
#[derive(Debug, Default)]
pub struct ExecutionDagValidated {
    /// All operation identifiers in declaration order.
    pub operations: Vec<Vec<u8>>,
    /// Topological stages. Each stage is a Vec of operation
    /// identifiers. Ops in the same stage have no dependency
    /// relationship between them.
    pub stages: Vec<Vec<Vec<u8>>>,
    /// Per-operation assigned stage index.
    pub op_stage: HashMap<Vec<u8>, u32>,
}

/// Build and validate the execution DAG from a slice of
/// ExecuteOperation canonical blobs.
///
/// Port of `CodeExecute.buildExecutionDAG` +
/// `ExecutionDAG.validateNoCycles` + `ExecutionDAG.computeStages`
/// (`compute_intrinsic_code_execute.go:373-579`).
///
/// PORT-HOLE: the `optimizeStagesWithConflicts` pass in Go
/// (`compute_intrinsic_code_execute.go:582-761`) re-packs stages using
/// per-op read/write sets for parallel-execution planning. That pass
/// is marked `TODO(2.2): Multiphasic locking` in Go and the extract
/// methods for intrinsic contexts return empty sets there, so the
/// current behavior is a topological-stage assignment. We keep that
/// topological pass here; the multiphasic re-packing is deferred.
pub fn build_execution_dag(
    execute_operations: &[Vec<u8>],
) -> Result<ExecutionDagValidated> {
    // 1. Non-empty, under-limit.
    if execute_operations.is_empty() {
        return Err(QuilError::InvalidArgument(
            "verify: invalid code execute: empty operations list".into(),
        ));
    }
    if execute_operations.len() > MAX_OPERATIONS_LIMIT {
        return Err(QuilError::InvalidArgument(format!(
            "verify: invalid code execute: operations count {} exceeds \
             limit {}",
            execute_operations.len(),
            MAX_OPERATIONS_LIMIT
        )));
    }

    // 2. Decode each operation; keep both the identifier and its
    //    declared dependencies. Fail on duplicate identifiers.
    let mut ops: Vec<ExecuteOperation> = Vec::with_capacity(execute_operations.len());
    let mut id_order: Vec<Vec<u8>> = Vec::with_capacity(execute_operations.len());
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    for raw in execute_operations {
        let op = ExecuteOperation::from_canonical_bytes(raw).map_err(|e| {
            QuilError::InvalidArgument(format!(
                "verify: invalid code execute: decoding operation: {}",
                e
            ))
        })?;

        // Decode and sanity-check the nested Application.
        let _app = Application::from_canonical_bytes(&op.application).map_err(|e| {
            QuilError::InvalidArgument(format!(
                "verify: invalid code execute: decoding application: {}",
                e
            ))
        })?;

        if !seen.insert(op.identifier.clone()) {
            return Err(QuilError::InvalidArgument(
                "verify: invalid code execute: duplicate operation \
                 identifier"
                    .into(),
            ));
        }
        id_order.push(op.identifier.clone());
        ops.push(op);
    }

    // 3. Build adjacency and per-node dependency/dependent maps.
    //    `deps[id]` = set of ids this op directly depends on.
    //    `dependents[id]` = set of ids that depend on this op.
    let mut deps: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();
    let mut dependents: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();
    for id in &id_order {
        deps.entry(id.clone()).or_default();
        dependents.entry(id.clone()).or_default();
    }
    for op in &ops {
        for dep in &op.dependencies {
            if !seen.contains(dep) {
                return Err(QuilError::InvalidArgument(format!(
                    "verify: invalid code execute: dependency {} not \
                     found for operation {}",
                    hex_short(dep),
                    hex_short(&op.identifier),
                )));
            }
            deps.get_mut(&op.identifier).unwrap().push(dep.clone());
            dependents.get_mut(dep).unwrap().push(op.identifier.clone());
        }
    }

    // 4. Cycle detection via DFS with a recursion stack.
    //    Mirrors `detectCycle` in Go.
    enum Mark { Unvisited, InProgress, Done }
    let mut state: HashMap<Vec<u8>, Mark> = HashMap::new();
    for id in &id_order {
        state.insert(id.clone(), Mark::Unvisited);
    }
    // Iterative DFS to avoid stack growth on large DAGs.
    for start in &id_order {
        if matches!(state[start], Mark::Done) {
            continue;
        }
        let mut stack: Vec<(Vec<u8>, usize)> = vec![(start.clone(), 0)];
        state.insert(start.clone(), Mark::InProgress);
        while let Some((node, idx)) = stack.last().cloned() {
            let children = &deps[&node];
            if idx < children.len() {
                // Advance iterator at current frame.
                let frame = stack.last_mut().unwrap();
                frame.1 = idx + 1;
                let child = &children[idx];
                match state[child] {
                    Mark::InProgress => {
                        return Err(QuilError::InvalidArgument(format!(
                            "verify: invalid code execute: cycle \
                             detected involving operation {}",
                            hex_short(child),
                        )));
                    }
                    Mark::Done => {}
                    Mark::Unvisited => {
                        state.insert(child.clone(), Mark::InProgress);
                        stack.push((child.clone(), 0));
                    }
                }
            } else {
                state.insert(node.clone(), Mark::Done);
                stack.pop();
            }
        }
    }

    // 5. Topological stage assignment (Kahn-style layering).
    //    `current_stage`: ops with all deps resolved at this level.
    let mut op_stage: HashMap<Vec<u8>, u32> = HashMap::new();
    let mut stages: Vec<Vec<Vec<u8>>> = Vec::new();
    let mut visited: HashSet<Vec<u8>> = HashSet::new();

    let mut current: Vec<Vec<u8>> = Vec::new();
    for id in &id_order {
        if deps[id].is_empty() {
            op_stage.insert(id.clone(), 0);
            current.push(id.clone());
        }
    }
    if current.is_empty() && !id_order.is_empty() {
        return Err(QuilError::InvalidArgument(
            "verify: invalid code execute: no operations without \
             dependencies found"
                .into(),
        ));
    }

    let mut processed_count = 0usize;
    while !current.is_empty() {
        processed_count += current.len();
        for id in &current {
            visited.insert(id.clone());
        }
        stages.push(current.clone());

        let mut next: Vec<Vec<u8>> = Vec::new();
        let mut next_seen: HashSet<Vec<u8>> = HashSet::new();
        for id in &current {
            for dep_id in &dependents[id] {
                if visited.contains(dep_id) {
                    continue;
                }
                // Check all deps of dep_id are visited.
                let mut all_done = true;
                let mut max_stage: u32 = 0;
                for d in &deps[dep_id] {
                    if !visited.contains(d) {
                        all_done = false;
                        break;
                    }
                    if let Some(&s) = op_stage.get(d) {
                        if s > max_stage {
                            max_stage = s;
                        }
                    }
                }
                if all_done && next_seen.insert(dep_id.clone()) {
                    op_stage.insert(dep_id.clone(), max_stage + 1);
                    next.push(dep_id.clone());
                }
            }
        }
        current = next;
    }

    if processed_count != id_order.len() {
        return Err(QuilError::InvalidArgument(
            "verify: invalid code execute: not all operations were \
             processed - possible disconnected graph"
                .into(),
        ));
    }

    Ok(ExecutionDagValidated {
        operations: id_order,
        stages,
        op_stage,
    })
}

/// Short hex prefix for error messages (8 chars of hex from the first
/// bytes).
fn hex_short(b: &[u8]) -> String {
    let take = b.len().min(4);
    let mut s = String::with_capacity(take * 2);
    for &byte in &b[..take] {
        use std::fmt::Write;
        let _ = write!(&mut s, "{:02x}", byte);
    }
    s
}

// =====================================================================
// CodeFinalize
// =====================================================================

/// Get the cost of a code finalization.
pub fn code_finalize_cost(
    results: &[Vec<u8>],
    state_changes: &[Vec<u8>],
) -> BigInt {
    let total: usize = results.iter().map(|r| r.len()).sum::<usize>()
        + state_changes.iter().map(|s| s.len()).sum::<usize>();
    BigInt::from(total as i64)
}

/// Create a state transition vertex for a finalized execution result.
pub fn create_state_transition_vertex(
    domain: &[u8; 32],
    address: &[u8],
    old_value: &[u8],
    new_value: &[u8],
) -> Result<quil_tries::VectorCommitmentTree> {
    let mut tree = quil_tries::VectorCommitmentTree::new();
    // Index 0: old value
    tree.insert(&[0x00], old_value, &[], &BigInt::from(old_value.len() as i64))
        .map_err(|e| QuilError::Internal(format!("state transition: {}", e)))?;
    // Index 1: new value
    tree.insert(&[1 << 2], new_value, &[], &BigInt::from(new_value.len() as i64))
        .map_err(|e| QuilError::Internal(format!("state transition: {}", e)))?;
    // Index 2: address
    tree.insert(&[2 << 2], address, &[], &BigInt::from(address.len() as i64))
        .map_err(|e| QuilError::Internal(format!("state transition: {}", e)))?;
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct AcceptCompiler;
    impl CircuitCompiler for AcceptCompiler {
        fn compile(&self, _source: &str, _input_sizes: &[Vec<i32>]) -> Result<Vec<u8>> {
            Ok(vec![0xAA; 100])
        }
        fn validate_circuit(&self, _circuit: &[u8]) -> Result<()> {
            Ok(())
        }
    }

    struct RejectCompiler;
    impl CircuitCompiler for RejectCompiler {
        fn compile(&self, _source: &str, _input_sizes: &[Vec<i32>]) -> Result<Vec<u8>> {
            Err(QuilError::InvalidArgument("compile failed".into()))
        }
        fn validate_circuit(&self, _circuit: &[u8]) -> Result<()> {
            Err(QuilError::InvalidArgument("invalid circuit".into()))
        }
    }

    #[test]
    fn verify_deployment_accepts_valid() {
        assert!(verify_code_deployment(&AcceptCompiler, b"circuit-bytes").unwrap());
    }

    #[test]
    fn verify_deployment_rejects_invalid() {
        assert!(verify_code_deployment(&RejectCompiler, b"bad").is_err());
    }

    #[test]
    fn deployment_cost_proportional_to_size() {
        assert_eq!(code_deployment_cost(&[0u8; 100]), BigInt::from(100));
        assert_eq!(code_deployment_cost(&[0u8; 0]), BigInt::from(0));
    }

    #[test]
    fn deployment_address_is_deterministic() {
        let a1 = code_deployment_address(&[0xAAu8; 32], b"circuit").unwrap();
        let a2 = code_deployment_address(&[0xAAu8; 32], b"circuit").unwrap();
        assert_eq!(a1, a2);
    }

    #[test]
    fn deployment_address_differs_by_circuit() {
        let a1 = code_deployment_address(&[0xAAu8; 32], b"circuit-a").unwrap();
        let a2 = code_deployment_address(&[0xAAu8; 32], b"circuit-b").unwrap();
        assert_ne!(a1, a2);
    }

    #[test]
    fn create_code_vertex_stores_circuit() {
        let circuit = b"test-circuit-bytecode";
        let tree = create_code_vertex_tree(circuit).unwrap();
        assert_eq!(tree.get(&[0x00]).unwrap(), circuit);
    }

    #[test]
    fn execute_cost() {
        let ops = vec![vec![0u8; 50], vec![0u8; 30]];
        assert_eq!(code_execute_cost(&ops), BigInt::from(80));
    }

    #[test]
    fn finalize_cost() {
        let results = vec![vec![0u8; 20]];
        let changes = vec![vec![0u8; 40], vec![0u8; 10]];
        assert_eq!(code_finalize_cost(&results, &changes), BigInt::from(70));
    }

    #[test]
    fn state_transition_vertex_stores_values() {
        let domain = [0xAAu8; 32];
        let tree = create_state_transition_vertex(
            &domain, b"addr", b"old-val", b"new-val",
        ).unwrap();
        assert_eq!(tree.get(&[0x00]).unwrap(), b"old-val");
        assert_eq!(tree.get(&[1 << 2]).unwrap(), b"new-val");
        assert_eq!(tree.get(&[2 << 2]).unwrap(), b"addr");
    }

    // =================================================================
    // verify_code_finalize
    // =================================================================

    struct AcceptKeyManager;
    impl KeyManager for AcceptKeyManager {
        fn validate_signature(&self, _: KeyType, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<bool> {
            Ok(true)
        }
    }
    struct RejectKeyManager;
    impl KeyManager for RejectKeyManager {
        fn validate_signature(&self, _: KeyType, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Result<bool> {
            Ok(false)
        }
    }
    struct CapturingKeyManager {
        captured: std::cell::RefCell<Option<(KeyType, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>>,
    }
    // Manual Send + Sync because of RefCell — we never share across threads in tests.
    unsafe impl Send for CapturingKeyManager {}
    unsafe impl Sync for CapturingKeyManager {}
    impl KeyManager for CapturingKeyManager {
        fn validate_signature(&self, kt: KeyType, pk: &[u8], msg: &[u8], sig: &[u8], dom: &[u8]) -> Result<bool> {
            *self.captured.borrow_mut() = Some((kt, pk.to_vec(), msg.to_vec(), sig.to_vec(), dom.to_vec()));
            Ok(true)
        }
    }

    fn sample_execution_result(op_id: &[u8]) -> Vec<u8> {
        super::super::ops::ExecutionResult {
            operation_id: op_id.to_vec(),
            success: true,
            output: vec![0xBB; 16],
            error: vec![],
        }.to_canonical_bytes().unwrap()
    }
    fn sample_state_change(domain: [u8; 32], address: Vec<u8>) -> Vec<u8> {
        super::super::ops::StateTransition {
            domain,
            address,
            old_value: vec![1; 8],
            new_value: vec![2; 8],
            proof: vec![],
        }.to_canonical_bytes().unwrap()
    }

    fn sample_finalize() -> CodeFinalize {
        CodeFinalize {
            rendezvous: [0x55u8; 32],
            results: vec![sample_execution_result(b"op-1")],
            // State change domain must match the compute app domain
            // used when calling verify_code_finalize below
            // ([0xDD; 32]). Cross-domain writes are rejected by the
            // verify path.
            state_changes: vec![sample_state_change([0xDDu8; 32], vec![0xBBu8; 32])],
            proof_of_execution: vec![0xCCu8; 114], // ed448 sig length
            message_output: vec![],
        }
    }

    #[test]
    fn finalize_verify_accepts_with_accept_key_manager() {
        let f = sample_finalize();
        let domain = [0xDDu8; 32];
        let pk = vec![0xEEu8; 57];
        assert!(verify_code_finalize(&f, &domain, &pk, &AcceptKeyManager).unwrap());
    }

    #[test]
    fn finalize_verify_rejects_empty_results() {
        let mut f = sample_finalize();
        f.results.clear();
        let domain = [0xDDu8; 32];
        let pk = vec![0xEEu8; 57];
        assert!(verify_code_finalize(&f, &domain, &pk, &AcceptKeyManager).is_err());
    }

    #[test]
    fn finalize_verify_rejects_invalid_sig() {
        let f = sample_finalize();
        let domain = [0xDDu8; 32];
        let pk = vec![0xEEu8; 57];
        assert!(verify_code_finalize(&f, &domain, &pk, &RejectKeyManager).is_err());
    }

    #[test]
    fn finalize_verify_rejects_bad_state_change_address_length() {
        let mut f = sample_finalize();
        // Replace state change with one whose address is not 32 bytes.
        f.state_changes = vec![sample_state_change([0xDDu8; 32], vec![0xBBu8; 31])];
        let domain = [0xDDu8; 32];
        let pk = vec![0xEEu8; 57];
        assert!(verify_code_finalize(&f, &domain, &pk, &AcceptKeyManager).is_err());
    }

    #[test]
    fn finalize_verify_rejects_cross_domain_state_change() {
        // State changes targeting other domains must be rejected.
        // The signed-finalize would otherwise let a compute-domain
        // key mutate state in another domain.
        let mut f = sample_finalize();
        f.state_changes = vec![sample_state_change([0xAAu8; 32], vec![0xBBu8; 32])];
        let domain = [0xDDu8; 32];
        let pk = vec![0xEEu8; 57];
        let err = verify_code_finalize(&f, &domain, &pk, &AcceptKeyManager).unwrap_err();
        assert!(format!("{err}").contains("differs from compute app domain"));
    }

    #[test]
    fn finalize_verify_passes_expected_args_to_key_manager() {
        let f = sample_finalize();
        let domain = [0xDDu8; 32];
        let pk = vec![0xEEu8; 57];
        let km = CapturingKeyManager { captured: std::cell::RefCell::new(None) };
        assert!(verify_code_finalize(&f, &domain, &pk, &km).unwrap());
        let cap = km.captured.borrow();
        let (kt, captured_pk, captured_msg, captured_sig, captured_dom) = cap.as_ref().unwrap();
        assert_eq!(*kt, KeyType::Ed448);
        assert_eq!(captured_pk, &pk);
        assert_eq!(captured_sig, &f.proof_of_execution);
        // Domain = compute_app_domain || "CODE_FINALIZE"
        assert_eq!(&captured_dom[..32], &domain);
        assert_eq!(&captured_dom[32..], CODE_FINALIZE_DOMAIN_TAG);
        // Message = canonical bytes of finalize with proof_of_execution cleared
        let mut expected = f.clone();
        expected.proof_of_execution.clear();
        assert_eq!(captured_msg, &expected.to_canonical_bytes().unwrap());
    }

    #[test]
    fn finalize_domain_concatenation_is_raw_bytes() {
        let d = [0xABu8; 32];
        let ctx = code_finalize_domain(&d);
        assert_eq!(ctx.len(), 32 + CODE_FINALIZE_DOMAIN_TAG.len());
        assert_eq!(&ctx[..32], &d);
        assert_eq!(&ctx[32..], CODE_FINALIZE_DOMAIN_TAG);
    }

    // =================================================================
    // verify_code_execute / build_execution_dag
    // =================================================================

    struct AcceptBP;
    impl BulletproofProver for AcceptBP {
        fn generate_range_proof(&self, _: &[Vec<u8>], _: &[u8], _: u64) -> Result<quil_types::crypto::RangeProofResult> { Err(QuilError::Internal("na".into())) }
        fn generate_input_commitments(&self, _: &[Vec<u8>], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_range_proof(&self, _: &[u8], _: &[u8], _: u64) -> bool { true }
        fn sum_check(&self, _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>]) -> bool { true }
        fn sign_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> bool { true }
        fn simple_sign(&self, _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn simple_verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool { true }
    }
    struct RejectBP;
    impl BulletproofProver for RejectBP {
        fn generate_range_proof(&self, _: &[Vec<u8>], _: &[u8], _: u64) -> Result<quil_types::crypto::RangeProofResult> { Err(QuilError::Internal("na".into())) }
        fn generate_input_commitments(&self, _: &[Vec<u8>], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_range_proof(&self, _: &[u8], _: &[u8], _: u64) -> bool { false }
        fn sum_check(&self, _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>], _: &[Vec<u8>]) -> bool { false }
        fn sign_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn verify_hidden(&self, _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8], _: &[u8]) -> bool { false }
        fn simple_sign(&self, _: &[u8], _: &[u8]) -> Vec<u8> { vec![] }
        fn simple_verify(&self, _: &[u8], _: &[u8], _: &[u8]) -> bool { false }
    }

    fn make_op(id: &[u8], deps: Vec<&[u8]>) -> Vec<u8> {
        let app = Application {
            address: vec![0u8; 32],
            execution_context: EXECUTION_CONTEXT_HYPERGRAPH,
        };
        ExecuteOperation {
            application: app.to_canonical_bytes().unwrap(),
            identifier: id.to_vec(),
            dependencies: deps.into_iter().map(|d| d.to_vec()).collect(),
        }
        .to_canonical_bytes()
        .unwrap()
    }

    #[test]
    fn dag_single_op_no_deps_one_stage() {
        let dag = build_execution_dag(&[make_op(b"a", vec![])]).unwrap();
        assert_eq!(dag.stages.len(), 1);
        assert_eq!(dag.stages[0].len(), 1);
        assert_eq!(dag.op_stage[&b"a".to_vec()], 0);
    }

    #[test]
    fn dag_chain_three_stages() {
        let ops = vec![
            make_op(b"a", vec![]),
            make_op(b"b", vec![b"a"]),
            make_op(b"c", vec![b"b"]),
        ];
        let dag = build_execution_dag(&ops).unwrap();
        assert_eq!(dag.stages.len(), 3);
        assert_eq!(dag.op_stage[&b"a".to_vec()], 0);
        assert_eq!(dag.op_stage[&b"b".to_vec()], 1);
        assert_eq!(dag.op_stage[&b"c".to_vec()], 2);
    }

    #[test]
    fn dag_parallel_siblings_same_stage() {
        // a -> b, a -> c; b and c are both at stage 1.
        let ops = vec![
            make_op(b"a", vec![]),
            make_op(b"b", vec![b"a"]),
            make_op(b"c", vec![b"a"]),
        ];
        let dag = build_execution_dag(&ops).unwrap();
        assert_eq!(dag.op_stage[&b"a".to_vec()], 0);
        assert_eq!(dag.op_stage[&b"b".to_vec()], 1);
        assert_eq!(dag.op_stage[&b"c".to_vec()], 1);
    }

    #[test]
    fn dag_rejects_empty() {
        assert!(build_execution_dag(&[]).is_err());
    }

    #[test]
    fn dag_rejects_cycle() {
        // a -> b -> a
        let ops = vec![
            make_op(b"a", vec![b"b"]),
            make_op(b"b", vec![b"a"]),
        ];
        assert!(build_execution_dag(&ops).is_err());
    }

    #[test]
    fn dag_rejects_self_cycle() {
        let ops = vec![make_op(b"a", vec![b"a"])];
        assert!(build_execution_dag(&ops).is_err());
    }

    #[test]
    fn dag_rejects_duplicate_identifiers() {
        let ops = vec![make_op(b"a", vec![]), make_op(b"a", vec![])];
        assert!(build_execution_dag(&ops).is_err());
    }

    #[test]
    fn dag_rejects_unknown_dependency() {
        let ops = vec![make_op(b"a", vec![b"ghost"])];
        assert!(build_execution_dag(&ops).is_err());
    }

    #[test]
    fn dag_rejects_over_limit() {
        let mut ops = Vec::with_capacity(MAX_OPERATIONS_LIMIT + 1);
        for i in 0..=MAX_OPERATIONS_LIMIT {
            let id = format!("op-{}", i);
            ops.push(make_op(id.as_bytes(), vec![]));
        }
        assert!(build_execution_dag(&ops).is_err());
    }

    #[test]
    fn dag_rejects_disconnected_cycle() {
        // a -> b (ok), plus a cycle c -> d -> c
        let ops = vec![
            make_op(b"a", vec![]),
            make_op(b"b", vec![b"a"]),
            make_op(b"c", vec![b"d"]),
            make_op(b"d", vec![b"c"]),
        ];
        assert!(build_execution_dag(&ops).is_err());
    }

    #[test]
    fn execute_verify_zero_payer_skips_signature() {
        let execute = CodeExecute {
            proof_of_payment: vec![vec![0u8; 56], vec![]], // zero payer
            domain: [0xAAu8; 32],
            rendezvous: [0xBBu8; 32],
            execute_operations: vec![make_op(b"a", vec![])],
        };
        // Even RejectBP should pass — we don't call simple_verify for zero payer.
        assert!(verify_code_execute(&execute, &RejectBP).unwrap());
    }

    #[test]
    fn execute_verify_real_payer_accept() {
        let execute = CodeExecute {
            proof_of_payment: vec![vec![0xAAu8; 56], vec![0xBBu8; 112]],
            domain: [0xAAu8; 32],
            rendezvous: [0xCCu8; 32],
            execute_operations: vec![make_op(b"a", vec![])],
        };
        assert!(verify_code_execute(&execute, &AcceptBP).unwrap());
    }

    #[test]
    fn execute_verify_real_payer_reject() {
        let execute = CodeExecute {
            proof_of_payment: vec![vec![0xAAu8; 56], vec![0xBBu8; 112]],
            domain: [0xAAu8; 32],
            rendezvous: [0xCCu8; 32],
            execute_operations: vec![make_op(b"a", vec![])],
        };
        assert!(verify_code_execute(&execute, &RejectBP).is_err());
    }

    #[test]
    fn execute_verify_rejects_empty_operations() {
        let execute = CodeExecute {
            proof_of_payment: vec![vec![0u8; 56], vec![]],
            domain: [0xAAu8; 32],
            rendezvous: [0xBBu8; 32],
            execute_operations: vec![],
        };
        assert!(verify_code_execute(&execute, &AcceptBP).is_err());
    }

    #[test]
    fn execute_verify_rejects_cycle_even_with_valid_payment() {
        let execute = CodeExecute {
            proof_of_payment: vec![vec![0u8; 56], vec![]],
            domain: [0xAAu8; 32],
            rendezvous: [0xBBu8; 32],
            execute_operations: vec![make_op(b"a", vec![b"b"]), make_op(b"b", vec![b"a"])],
        };
        assert!(verify_code_execute(&execute, &AcceptBP).is_err());
    }

    #[test]
    fn execute_verify_real_payer_missing_signature() {
        // proof_of_payment[0] is non-zero payer but there's no
        // proof_of_payment[1].
        let execute = CodeExecute {
            proof_of_payment: vec![vec![0xAAu8; 56]],
            domain: [0xAAu8; 32],
            rendezvous: [0xBBu8; 32],
            execute_operations: vec![make_op(b"a", vec![])],
        };
        assert!(verify_code_execute(&execute, &AcceptBP).is_err());
    }
}
