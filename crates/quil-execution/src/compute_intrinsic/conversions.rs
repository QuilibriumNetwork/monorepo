//! Conversions between prost-generated compute proto types and the
//! canonical-bytes types in this module.

use quil_types::error::Result;
use quil_types::proto::compute as pb;
use quil_types::proto::keys as keys_pb;

use super::config::{ComputeConfiguration, ComputeDeploy, ComputeUpdate};
use super::ops::{
    Application, CodeDeployment, CodeExecute, CodeFinalize, ExecuteOperation,
    ExecutionResult, StateTransition,
};

// =====================================================================
// ComputeConfiguration
// =====================================================================

pub fn compute_config_from_proto(p: &pb::ComputeConfiguration) -> ComputeConfiguration {
    ComputeConfiguration {
        read_public_key: p.read_public_key.clone(),
        write_public_key: p.write_public_key.clone(),
        owner_public_key: p.owner_public_key.clone(),
    }
}

pub fn compute_config_to_proto(c: &ComputeConfiguration) -> pb::ComputeConfiguration {
    pb::ComputeConfiguration {
        read_public_key: c.read_public_key.clone(),
        write_public_key: c.write_public_key.clone(),
        owner_public_key: c.owner_public_key.clone(),
    }
}

// =====================================================================
// ComputeDeploy / ComputeUpdate
// =====================================================================

pub fn compute_deploy_from_proto(p: &pb::ComputeDeploy) -> Result<ComputeDeploy> {
    let config = match &p.config {
        Some(c) => compute_config_from_proto(c).to_canonical_bytes()?,
        None => Vec::new(),
    };
    Ok(ComputeDeploy { config, rdf_schema: p.rdf_schema.clone() })
}

pub fn compute_deploy_to_proto(d: &ComputeDeploy) -> Result<pb::ComputeDeploy> {
    let config = if !d.config.is_empty() {
        Some(compute_config_to_proto(
            &ComputeConfiguration::from_canonical_bytes(&d.config)?,
        ))
    } else {
        None
    };
    Ok(pb::ComputeDeploy { config, rdf_schema: d.rdf_schema.clone() })
}

pub fn compute_update_from_proto(p: &pb::ComputeUpdate) -> Result<ComputeUpdate> {
    let config = match &p.config {
        Some(c) => compute_config_from_proto(c).to_canonical_bytes()?,
        None => Vec::new(),
    };
    // Raw Falcon signature bytes (verify uses the field directly — no 0x011C
    // aggregate envelope). Matches the token-update fix.
    let sig = match &p.public_key_signature_bls48581 {
        Some(s) => s.signature.clone(),
        None => Vec::new(),
    };
    Ok(ComputeUpdate { config, rdf_schema: p.rdf_schema.clone(), public_key_signature_bls48581: sig })
}

pub fn compute_update_to_proto(u: &ComputeUpdate) -> Result<pb::ComputeUpdate> {
    let config = if !u.config.is_empty() {
        Some(compute_config_to_proto(
            &ComputeConfiguration::from_canonical_bytes(&u.config)?,
        ))
    } else {
        None
    };
    let public_key_signature_bls48581 = if u.public_key_signature_bls48581.is_empty() {
        None
    } else {
        Some(keys_pb::Bls48581AggregateSignature {
            signature: u.public_key_signature_bls48581.clone(),
            public_key: None,
            bitmask: Vec::new(),
        })
    };
    Ok(pb::ComputeUpdate {
        config,
        rdf_schema: u.rdf_schema.clone(),
        public_key_signature_bls48581,
    })
}

// =====================================================================
// CodeDeployment
// =====================================================================

pub fn code_deployment_from_proto(p: &pb::CodeDeployment) -> CodeDeployment {
    let mut domain = [0u8; 32];
    if p.domain.len() >= 32 {
        domain.copy_from_slice(&p.domain[..32]);
    }
    CodeDeployment {
        circuit: p.circuit.clone(),
        input_types: p.input_types.iter().map(|s| s.as_bytes().to_vec()).collect(),
        output_types: p.output_types.iter().map(|s| s.as_bytes().to_vec()).collect(),
        domain,
    }
}

pub fn code_deployment_to_proto(d: &CodeDeployment) -> pb::CodeDeployment {
    pb::CodeDeployment {
        circuit: d.circuit.clone(),
        input_types: d.input_types.iter().map(|b| String::from_utf8_lossy(b).into_owned()).collect(),
        output_types: d.output_types.iter().map(|b| String::from_utf8_lossy(b).into_owned()).collect(),
        domain: d.domain.to_vec(),
    }
}

// =====================================================================
// Application / ExecuteOperation
// =====================================================================

pub fn application_from_proto(p: &pb::Application) -> Application {
    Application {
        address: p.address.clone(),
        execution_context: p.execution_context as u32,
    }
}

pub fn execute_operation_from_proto(p: &pb::ExecuteOperation) -> Result<ExecuteOperation> {
    let application = match &p.application {
        Some(a) => application_from_proto(a).to_canonical_bytes()?,
        None => Vec::new(),
    };
    Ok(ExecuteOperation {
        application,
        identifier: p.identifier.clone(),
        dependencies: p.dependencies.clone(),
    })
}

pub fn application_to_proto(a: &Application) -> pb::Application {
    pb::Application {
        address: a.address.clone(),
        execution_context: a.execution_context as i32,
    }
}

pub fn execute_operation_to_proto(o: &ExecuteOperation) -> Result<pb::ExecuteOperation> {
    let application = if o.application.is_empty() {
        None
    } else {
        Some(application_to_proto(&Application::from_canonical_bytes(&o.application)?))
    };
    Ok(pb::ExecuteOperation {
        application,
        identifier: o.identifier.clone(),
        dependencies: o.dependencies.clone(),
    })
}

// =====================================================================
// CodeExecute
// =====================================================================

pub fn code_execute_from_proto(p: &pb::CodeExecute) -> Result<CodeExecute> {
    let mut domain = [0u8; 32];
    if p.domain.len() >= 32 { domain.copy_from_slice(&p.domain[..32]); }
    let mut rendezvous = [0u8; 32];
    if p.rendezvous.len() >= 32 { rendezvous.copy_from_slice(&p.rendezvous[..32]); }
    let ops: Vec<Vec<u8>> = p.execute_operations.iter()
        .map(|o| execute_operation_from_proto(o))
        .collect::<Result<Vec<_>>>()?
        .iter()
        .map(|o| o.to_canonical_bytes())
        .collect::<Result<Vec<_>>>()?;
    Ok(CodeExecute {
        proof_of_payment: p.proof_of_payment.clone(),
        domain, rendezvous, execute_operations: ops,
    })
}

pub fn code_execute_to_proto(e: &CodeExecute) -> Result<pb::CodeExecute> {
    let execute_operations: Vec<pb::ExecuteOperation> = e
        .execute_operations
        .iter()
        .map(|b| execute_operation_to_proto(&ExecuteOperation::from_canonical_bytes(b)?))
        .collect::<Result<Vec<_>>>()?;
    Ok(pb::CodeExecute {
        proof_of_payment: e.proof_of_payment.clone(),
        domain: e.domain.to_vec(),
        rendezvous: e.rendezvous.to_vec(),
        execute_operations,
    })
}

// =====================================================================
// CodeFinalize
// =====================================================================

pub fn execution_result_from_proto(p: &pb::ExecutionResult) -> ExecutionResult {
    ExecutionResult {
        operation_id: p.operation_id.clone(),
        success: p.success,
        output: p.output.clone(),
        error: p.error.clone(),
    }
}

pub fn state_transition_from_proto(p: &pb::StateTransition) -> StateTransition {
    let mut domain = [0u8; 32];
    if p.domain.len() >= 32 { domain.copy_from_slice(&p.domain[..32]); }
    StateTransition {
        domain, address: p.address.clone(),
        old_value: p.old_value.clone(), new_value: p.new_value.clone(),
        proof: p.proof.clone(),
    }
}

pub fn code_finalize_from_proto(p: &pb::CodeFinalize) -> Result<CodeFinalize> {
    let mut rendezvous = [0u8; 32];
    if p.rendezvous.len() >= 32 { rendezvous.copy_from_slice(&p.rendezvous[..32]); }
    let results: Vec<Vec<u8>> = p.results.iter()
        .map(|r| execution_result_from_proto(r).to_canonical_bytes())
        .collect::<Result<Vec<_>>>()?;
    let state_changes: Vec<Vec<u8>> = p.state_changes.iter()
        .map(|s| state_transition_from_proto(s).to_canonical_bytes())
        .collect::<Result<Vec<_>>>()?;
    Ok(CodeFinalize {
        rendezvous, results, state_changes,
        proof_of_execution: p.proof_of_execution.clone(),
        message_output: p.message_output.clone(),
    })
}

pub fn execution_result_to_proto(r: &ExecutionResult) -> pb::ExecutionResult {
    pb::ExecutionResult {
        operation_id: r.operation_id.clone(),
        success: r.success,
        output: r.output.clone(),
        error: r.error.clone(),
    }
}

pub fn state_transition_to_proto(s: &StateTransition) -> pb::StateTransition {
    pb::StateTransition {
        domain: s.domain.to_vec(),
        address: s.address.clone(),
        old_value: s.old_value.clone(),
        new_value: s.new_value.clone(),
        proof: s.proof.clone(),
    }
}

pub fn code_finalize_to_proto(f: &CodeFinalize) -> Result<pb::CodeFinalize> {
    let results: Vec<pb::ExecutionResult> = f
        .results
        .iter()
        .map(|b| Ok(execution_result_to_proto(&ExecutionResult::from_canonical_bytes(b)?)))
        .collect::<Result<Vec<_>>>()?;
    let state_changes: Vec<pb::StateTransition> = f
        .state_changes
        .iter()
        .map(|b| Ok(state_transition_to_proto(&StateTransition::from_canonical_bytes(b)?)))
        .collect::<Result<Vec<_>>>()?;
    Ok(pb::CodeFinalize {
        rendezvous: f.rendezvous.to_vec(),
        results,
        state_changes,
        proof_of_execution: f.proof_of_execution.clone(),
        message_output: f.message_output.clone(),
    })
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_config_round_trip() {
        let pb = pb::ComputeConfiguration {
            read_public_key: vec![1u8; 1158],
            write_public_key: vec![2u8; 57],
            owner_public_key: vec![3u8; 585],
        };
        let c = compute_config_from_proto(&pb);
        let back = compute_config_to_proto(&c);
        assert_eq!(back, pb);
    }

    #[test]
    fn compute_deploy_round_trip() {
        let pb = pb::ComputeDeploy {
            config: Some(pb::ComputeConfiguration {
                read_public_key: vec![1u8; 1158],
                write_public_key: vec![2u8; 57],
                owner_public_key: vec![],
            }),
            rdf_schema: b"schema".to_vec(),
        };
        let d = compute_deploy_from_proto(&pb).unwrap();
        let back = compute_deploy_to_proto(&d).unwrap();
        assert_eq!(back, pb);
    }

    #[test]
    fn code_deployment_round_trip() {
        let pb = pb::CodeDeployment {
            circuit: vec![0xAAu8; 100],
            input_types: vec!["uint64".into()],
            output_types: vec!["bool".into()],
            domain: vec![0x11u8; 32],
        };
        let d = code_deployment_from_proto(&pb);
        let back = code_deployment_to_proto(&d);
        assert_eq!(back, pb);
    }

    #[test]
    fn compute_config_full_pipeline() {
        let pb = pb::ComputeConfiguration {
            read_public_key: vec![0xAAu8; 1158],
            write_public_key: vec![0xBBu8; 57],
            owner_public_key: vec![0xCCu8; 585],
        };
        let c = compute_config_from_proto(&pb);
        let cb = c.to_canonical_bytes().unwrap();
        let c2 = ComputeConfiguration::from_canonical_bytes(&cb).unwrap();
        let back = compute_config_to_proto(&c2);
        assert_eq!(back, pb);
    }
}
