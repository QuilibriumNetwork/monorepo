//! Compute intrinsic canonical-bytes. Port of
//! `protobufs/compute.go` ToCanonicalBytes/FromCanonicalBytes for all
//! 16 compute types (0x0600–0x060F).

pub mod config;
pub mod conversions;
pub mod intrinsic;
pub mod materialize;
pub mod ops;

pub use config::{
    ComputeConfiguration, ComputeDeploy, ComputeUpdate,
    TYPE_COMPUTE_CONFIGURATION, TYPE_COMPUTE_DEPLOY, TYPE_COMPUTE_UPDATE,
};
pub use ops::{
    Application, CodeDeployment, CodeExecute, CodeFinalize, ExecuteOperation,
    ExecutionDag, ExecutionDependency, ExecutionNode, ExecutionResult,
    ExecutionStage, IntrinsicExecutionInput, IntrinsicExecutionOutput,
    StateTransition, TYPE_APPLICATION, TYPE_CODE_DEPLOYMENT, TYPE_CODE_EXECUTE,
    TYPE_CODE_FINALIZE, TYPE_EXECUTE_OPERATION, TYPE_EXECUTION_DAG,
    TYPE_EXECUTION_DEPENDENCY, TYPE_EXECUTION_NODE, TYPE_EXECUTION_RESULT,
    TYPE_EXECUTION_STAGE, TYPE_INTRINSIC_EXECUTION_INPUT,
    TYPE_INTRINSIC_EXECUTION_OUTPUT, TYPE_STATE_TRANSITION,
};

// Reuse the same cursor helpers from token_intrinsic
pub(crate) use crate::token_intrinsic::cursor;
