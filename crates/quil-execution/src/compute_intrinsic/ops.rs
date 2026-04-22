//! Compute operation types: CodeDeployment (0x0603) through
//! CodeFinalize (0x060F).

use quil_types::error::Result;
use super::cursor::*;

pub const TYPE_CODE_DEPLOYMENT: u32 = 0x0603;
pub const TYPE_APPLICATION: u32 = 0x0604;
pub const TYPE_INTRINSIC_EXECUTION_INPUT: u32 = 0x0605;
pub const TYPE_INTRINSIC_EXECUTION_OUTPUT: u32 = 0x0606;
pub const TYPE_EXECUTION_DEPENDENCY: u32 = 0x0607;
pub const TYPE_EXECUTE_OPERATION: u32 = 0x0608;
pub const TYPE_EXECUTION_NODE: u32 = 0x0609;
pub const TYPE_EXECUTION_DAG: u32 = 0x060A;
pub const TYPE_EXECUTION_STAGE: u32 = 0x060B;
pub const TYPE_CODE_EXECUTE: u32 = 0x060C;
pub const TYPE_STATE_TRANSITION: u32 = 0x060D;
pub const TYPE_EXECUTION_RESULT: u32 = 0x060E;
pub const TYPE_CODE_FINALIZE: u32 = 0x060F;

// -- CodeDeployment --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CodeDeployment {
    pub circuit: Vec<u8>,
    pub input_types: Vec<Vec<u8>>,
    pub output_types: Vec<Vec<u8>>,
    pub domain: [u8; 32],
}

impl CodeDeployment {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_CODE_DEPLOYMENT);
        put_lp(&mut out, &self.circuit);
        write_array(&mut out, &self.input_types);
        write_array(&mut out, &self.output_types);
        out.extend_from_slice(&self.domain);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_CODE_DEPLOYMENT, "CodeDeployment")?;
        let circuit = read_lp(data, &mut c)?;
        let input_types = read_array(data, &mut c)?;
        let output_types = read_array(data, &mut c)?;
        let d = read_bytes(data, &mut c, 32)?;
        let mut domain = [0u8; 32]; domain.copy_from_slice(&d);
        Ok(Self { circuit, input_types, output_types, domain })
    }
}

// -- Application --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Application {
    pub address: Vec<u8>,
    pub execution_context: u32,
}

impl Application {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_APPLICATION);
        put_lp(&mut out, &self.address);
        put_u32(&mut out, self.execution_context);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_APPLICATION, "Application")?;
        Ok(Self { address: read_lp(data, &mut c)?, execution_context: read_u32(data, &mut c)? })
    }
}

// -- IntrinsicExecutionInput --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntrinsicExecutionInput {
    pub address: Vec<u8>,
    pub input: Vec<u8>,
}

impl IntrinsicExecutionInput {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_INTRINSIC_EXECUTION_INPUT);
        put_lp(&mut out, &self.address);
        put_lp(&mut out, &self.input);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_INTRINSIC_EXECUTION_INPUT, "IntrinsicExecutionInput")?;
        Ok(Self { address: read_lp(data, &mut c)?, input: read_lp(data, &mut c)? })
    }
}

// -- IntrinsicExecutionOutput --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IntrinsicExecutionOutput {
    pub address: Vec<u8>,
    pub output: Vec<u8>,
    pub proof: Vec<u8>,
}

impl IntrinsicExecutionOutput {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_INTRINSIC_EXECUTION_OUTPUT);
        put_lp(&mut out, &self.address);
        put_lp(&mut out, &self.output);
        put_lp(&mut out, &self.proof);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_INTRINSIC_EXECUTION_OUTPUT, "IntrinsicExecutionOutput")?;
        Ok(Self { address: read_lp(data, &mut c)?, output: read_lp(data, &mut c)?, proof: read_lp(data, &mut c)? })
    }
}

// -- ExecutionDependency --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutionDependency {
    pub identifier: Vec<u8>,
    pub read_set: Vec<Vec<u8>>,
    pub write_set: Vec<Vec<u8>>,
    pub stage: u32,
}

impl ExecutionDependency {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_EXECUTION_DEPENDENCY);
        put_lp(&mut out, &self.identifier);
        write_array(&mut out, &self.read_set);
        write_array(&mut out, &self.write_set);
        put_u32(&mut out, self.stage);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_EXECUTION_DEPENDENCY, "ExecutionDependency")?;
        Ok(Self { identifier: read_lp(data, &mut c)?, read_set: read_array(data, &mut c)?, write_set: read_array(data, &mut c)?, stage: read_u32(data, &mut c)? })
    }
}

// -- ExecuteOperation --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecuteOperation {
    pub application: Vec<u8>, // nested Application canonical bytes
    pub identifier: Vec<u8>,
    pub dependencies: Vec<Vec<u8>>,
}

impl ExecuteOperation {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_EXECUTE_OPERATION);
        put_lp(&mut out, &self.application);
        put_lp(&mut out, &self.identifier);
        write_array(&mut out, &self.dependencies);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_EXECUTE_OPERATION, "ExecuteOperation")?;
        Ok(Self { application: read_lp(data, &mut c)?, identifier: read_lp(data, &mut c)?, dependencies: read_array(data, &mut c)? })
    }
}

// -- ExecutionNode --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutionNode {
    pub operation: Vec<u8>, // nested ExecuteOperation
    pub read_set: Vec<Vec<u8>>,
    pub write_set: Vec<Vec<u8>>,
    pub stage: u32,
    pub visited: bool,
    pub in_progress: bool,
}

impl ExecutionNode {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_EXECUTION_NODE);
        put_lp(&mut out, &self.operation);
        write_array(&mut out, &self.read_set);
        write_array(&mut out, &self.write_set);
        put_u32(&mut out, self.stage);
        out.push(if self.visited { 1 } else { 0 });
        out.push(if self.in_progress { 1 } else { 0 });
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_EXECUTION_NODE, "ExecutionNode")?;
        let operation = read_lp(data, &mut c)?;
        let read_set = read_array(data, &mut c)?;
        let write_set = read_array(data, &mut c)?;
        let stage = read_u32(data, &mut c)?;
        let visited = if c < data.len() { data[c] != 0 } else { false }; if c < data.len() { c += 1; }
        let in_progress = if c < data.len() { data[c] != 0 } else { false };
        Ok(Self { operation, read_set, write_set, stage, visited, in_progress })
    }
}

// -- ExecutionStage --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutionStage {
    pub operation_ids: Vec<Vec<u8>>,
}

impl ExecutionStage {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_EXECUTION_STAGE);
        write_array(&mut out, &self.operation_ids);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_EXECUTION_STAGE, "ExecutionStage")?;
        Ok(Self { operation_ids: read_array(data, &mut c)? })
    }
}

// -- ExecutionDAG --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutionDag {
    /// Map entries as (key_string, node_canonical_bytes) pairs.
    pub operations: Vec<(Vec<u8>, Vec<u8>)>,
    pub stages: Vec<Vec<u8>>, // nested ExecutionStage canonical bytes
}

impl ExecutionDag {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_EXECUTION_DAG);
        put_u32(&mut out, self.operations.len() as u32);
        for (key, node) in &self.operations {
            put_lp(&mut out, key);
            put_lp(&mut out, node);
        }
        write_array(&mut out, &self.stages);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_EXECUTION_DAG, "ExecutionDAG")?;
        let n = read_u32(data, &mut c)? as usize;
        let mut operations = Vec::with_capacity(n);
        for _ in 0..n {
            let key = read_lp(data, &mut c)?;
            let node = read_lp(data, &mut c)?;
            operations.push((key, node));
        }
        let stages = read_array(data, &mut c)?;
        Ok(Self { operations, stages })
    }
}

// -- CodeExecute --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CodeExecute {
    pub proof_of_payment: Vec<Vec<u8>>,
    pub domain: [u8; 32],
    pub rendezvous: [u8; 32],
    pub execute_operations: Vec<Vec<u8>>, // nested ExecuteOperation
}

impl CodeExecute {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_CODE_EXECUTE);
        write_array(&mut out, &self.proof_of_payment);
        out.extend_from_slice(&self.domain);
        out.extend_from_slice(&self.rendezvous);
        write_array(&mut out, &self.execute_operations);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_CODE_EXECUTE, "CodeExecute")?;
        let proof_of_payment = read_array(data, &mut c)?;
        let d = read_bytes(data, &mut c, 32)?;
        let r = read_bytes(data, &mut c, 32)?;
        let mut domain = [0u8; 32]; domain.copy_from_slice(&d);
        let mut rendezvous = [0u8; 32]; rendezvous.copy_from_slice(&r);
        let execute_operations = read_array(data, &mut c)?;
        Ok(Self { proof_of_payment, domain, rendezvous, execute_operations })
    }
}

// -- StateTransition --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StateTransition {
    pub domain: [u8; 32],
    pub address: Vec<u8>,
    pub old_value: Vec<u8>,
    pub new_value: Vec<u8>,
    pub proof: Vec<u8>,
}

impl StateTransition {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_STATE_TRANSITION);
        out.extend_from_slice(&self.domain);
        put_lp(&mut out, &self.address);
        put_lp(&mut out, &self.old_value);
        put_lp(&mut out, &self.new_value);
        put_lp(&mut out, &self.proof);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_STATE_TRANSITION, "StateTransition")?;
        let d = read_bytes(data, &mut c, 32)?;
        let mut domain = [0u8; 32]; domain.copy_from_slice(&d);
        Ok(Self { domain, address: read_lp(data, &mut c)?, old_value: read_lp(data, &mut c)?, new_value: read_lp(data, &mut c)?, proof: read_lp(data, &mut c)? })
    }
}

// -- ExecutionResult --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExecutionResult {
    pub operation_id: Vec<u8>,
    pub success: bool,
    pub output: Vec<u8>,
    pub error: Vec<u8>,
}

impl ExecutionResult {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_EXECUTION_RESULT);
        put_lp(&mut out, &self.operation_id);
        out.push(if self.success { 1 } else { 0 });
        put_lp(&mut out, &self.output);
        put_lp(&mut out, &self.error);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_EXECUTION_RESULT, "ExecutionResult")?;
        let operation_id = read_lp(data, &mut c)?;
        let success = if c < data.len() { data[c] != 0 } else { false }; if c < data.len() { c += 1; }
        Ok(Self { operation_id, success, output: read_lp(data, &mut c)?, error: read_lp(data, &mut c)? })
    }
}

// -- CodeFinalize --
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CodeFinalize {
    pub rendezvous: [u8; 32],
    pub results: Vec<Vec<u8>>,       // nested ExecutionResult
    pub state_changes: Vec<Vec<u8>>, // nested StateTransition
    pub proof_of_execution: Vec<u8>,
    pub message_output: Vec<u8>,
}

impl CodeFinalize {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        put_u32(&mut out, TYPE_CODE_FINALIZE);
        out.extend_from_slice(&self.rendezvous);
        write_array(&mut out, &self.results);
        write_array(&mut out, &self.state_changes);
        put_lp(&mut out, &self.proof_of_execution);
        put_lp(&mut out, &self.message_output);
        Ok(out)
    }
    pub fn from_canonical_bytes(data: &[u8]) -> Result<Self> {
        let mut c = 0;
        expect_tp(read_u32(data, &mut c)?, TYPE_CODE_FINALIZE, "CodeFinalize")?;
        let r = read_bytes(data, &mut c, 32)?;
        let mut rendezvous = [0u8; 32]; rendezvous.copy_from_slice(&r);
        Ok(Self {
            rendezvous,
            results: read_array(data, &mut c)?,
            state_changes: read_array(data, &mut c)?,
            proof_of_execution: read_lp(data, &mut c)?,
            message_output: read_lp(data, &mut c)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn code_deployment_round_trip() {
        let d = CodeDeployment { circuit: vec![0xAAu8; 100], input_types: vec![b"uint64".to_vec()], output_types: vec![b"bool".to_vec()], domain: [0x11u8; 32] };
        let b = d.to_canonical_bytes().unwrap();
        assert_eq!(CodeDeployment::from_canonical_bytes(&b).unwrap(), d);
    }
    #[test] fn application_round_trip() {
        let a = Application { address: vec![0xAAu8; 32], execution_context: 1 };
        let b = a.to_canonical_bytes().unwrap();
        assert_eq!(Application::from_canonical_bytes(&b).unwrap(), a);
    }
    #[test] fn intrinsic_input_round_trip() {
        let i = IntrinsicExecutionInput { address: vec![1u8; 32], input: vec![2u8; 64] };
        let b = i.to_canonical_bytes().unwrap();
        assert_eq!(IntrinsicExecutionInput::from_canonical_bytes(&b).unwrap(), i);
    }
    #[test] fn intrinsic_output_round_trip() {
        let o = IntrinsicExecutionOutput { address: vec![1u8; 32], output: vec![2u8; 64], proof: vec![3u8; 32] };
        let b = o.to_canonical_bytes().unwrap();
        assert_eq!(IntrinsicExecutionOutput::from_canonical_bytes(&b).unwrap(), o);
    }
    #[test] fn execution_dependency_round_trip() {
        let d = ExecutionDependency { identifier: b"op-1".to_vec(), read_set: vec![vec![1u8; 32]], write_set: vec![vec![2u8; 32]], stage: 0 };
        let b = d.to_canonical_bytes().unwrap();
        assert_eq!(ExecutionDependency::from_canonical_bytes(&b).unwrap(), d);
    }
    #[test] fn execute_operation_round_trip() {
        let o = ExecuteOperation { application: Application { address: vec![1u8; 32], execution_context: 0 }.to_canonical_bytes().unwrap(), identifier: b"exec-1".to_vec(), dependencies: vec![] };
        let b = o.to_canonical_bytes().unwrap();
        assert_eq!(ExecuteOperation::from_canonical_bytes(&b).unwrap(), o);
    }
    #[test] fn execution_node_round_trip() {
        let n = ExecutionNode { operation: vec![0xAAu8; 20], read_set: vec![], write_set: vec![], stage: 1, visited: true, in_progress: false };
        let b = n.to_canonical_bytes().unwrap();
        assert_eq!(ExecutionNode::from_canonical_bytes(&b).unwrap(), n);
    }
    #[test] fn execution_stage_round_trip() {
        let s = ExecutionStage { operation_ids: vec![b"op-1".to_vec(), b"op-2".to_vec()] };
        let b = s.to_canonical_bytes().unwrap();
        assert_eq!(ExecutionStage::from_canonical_bytes(&b).unwrap(), s);
    }
    #[test] fn execution_dag_round_trip() {
        let d = ExecutionDag { operations: vec![(b"key-1".to_vec(), vec![0xBBu8; 10])], stages: vec![ExecutionStage { operation_ids: vec![b"op-1".to_vec()] }.to_canonical_bytes().unwrap()] };
        let b = d.to_canonical_bytes().unwrap();
        assert_eq!(ExecutionDag::from_canonical_bytes(&b).unwrap(), d);
    }
    #[test] fn code_execute_round_trip() {
        let e = CodeExecute { proof_of_payment: vec![vec![0, 100]], domain: [0x11u8; 32], rendezvous: [0x22u8; 32], execute_operations: vec![] };
        let b = e.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_CODE_EXECUTE.to_be_bytes());
        assert_eq!(CodeExecute::from_canonical_bytes(&b).unwrap(), e);
    }
    #[test] fn state_transition_round_trip() {
        let s = StateTransition { domain: [0xAAu8; 32], address: vec![1u8; 32], old_value: vec![2u8; 10], new_value: vec![3u8; 10], proof: vec![4u8; 64] };
        let b = s.to_canonical_bytes().unwrap();
        assert_eq!(StateTransition::from_canonical_bytes(&b).unwrap(), s);
    }
    #[test] fn execution_result_round_trip() {
        let r = ExecutionResult { operation_id: b"op-1".to_vec(), success: true, output: vec![0xAAu8; 32], error: vec![] };
        let b = r.to_canonical_bytes().unwrap();
        assert_eq!(ExecutionResult::from_canonical_bytes(&b).unwrap(), r);
    }
    #[test] fn code_finalize_round_trip() {
        let f = CodeFinalize { rendezvous: [0x33u8; 32], results: vec![], state_changes: vec![], proof_of_execution: vec![0xFFu8; 64], message_output: vec![] };
        let b = f.to_canonical_bytes().unwrap();
        assert_eq!(&b[..4], &TYPE_CODE_FINALIZE.to_be_bytes());
        assert_eq!(CodeFinalize::from_canonical_bytes(&b).unwrap(), f);
    }
    #[test] fn all_type_prefixes_distinct() {
        use std::collections::HashSet;
        let ids: HashSet<u32> = [TYPE_CODE_DEPLOYMENT, TYPE_APPLICATION, TYPE_INTRINSIC_EXECUTION_INPUT, TYPE_INTRINSIC_EXECUTION_OUTPUT, TYPE_EXECUTION_DEPENDENCY, TYPE_EXECUTE_OPERATION, TYPE_EXECUTION_NODE, TYPE_EXECUTION_DAG, TYPE_EXECUTION_STAGE, TYPE_CODE_EXECUTE, TYPE_STATE_TRANSITION, TYPE_EXECUTION_RESULT, TYPE_CODE_FINALIZE].into_iter().collect();
        assert_eq!(ids.len(), 13);
    }
    #[test] fn empty_defaults_all_round_trip() {
        // Every type should round-trip from its Default
        CodeDeployment::from_canonical_bytes(&CodeDeployment::default().to_canonical_bytes().unwrap()).unwrap();
        Application::from_canonical_bytes(&Application::default().to_canonical_bytes().unwrap()).unwrap();
        ExecutionStage::from_canonical_bytes(&ExecutionStage::default().to_canonical_bytes().unwrap()).unwrap();
        ExecutionDag::from_canonical_bytes(&ExecutionDag::default().to_canonical_bytes().unwrap()).unwrap();
        CodeExecute::from_canonical_bytes(&CodeExecute::default().to_canonical_bytes().unwrap()).unwrap();
        StateTransition::from_canonical_bytes(&StateTransition::default().to_canonical_bytes().unwrap()).unwrap();
        ExecutionResult::from_canonical_bytes(&ExecutionResult::default().to_canonical_bytes().unwrap()).unwrap();
        CodeFinalize::from_canonical_bytes(&CodeFinalize::default().to_canonical_bytes().unwrap()).unwrap();
    }
}
