use crate::error::Result;
use crate::proto;
use num_bigint::BigInt;

/// Result of processing a message through an execution engine.
#[derive(Debug, Clone)]
pub struct ProcessMessageResult {
    /// Output messages to be included in the frame.
    pub messages: Vec<Vec<u8>>,
    /// Serialized state changes.
    pub state: Vec<u8>,
}

/// State change event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateChangeEvent {
    Initialize,
    Create,
    Update,
    Delete,
}

/// A single state change record in a changeset. The execution layer
/// accumulates these during `process_message` and commits them
/// atomically at the end of the frame.
#[derive(Debug, Clone)]
pub struct StateChange {
    /// The 32-byte domain (app address or GLOBAL).
    pub domain: Vec<u8>,
    /// The 32-byte data address within the domain.
    pub address: Vec<u8>,
    /// Discriminator distinguishing vertex adds/removes from hyperedge
    /// adds/removes. Poseidon hash of e.g. "vertex:adds".
    pub discriminator: Vec<u8>,
    /// The type of state change.
    pub state_change: StateChangeEvent,
    /// The serialized data payload for this change.
    pub value: Vec<u8>,
}

/// A shard execution engine that validates, processes, and proves messages.
pub trait ShardExecutionEngine: Send + Sync {
    /// Downcast hook for mutating concrete-type configuration after
    /// construction (e.g. installing optional intrinsic dependencies).
    /// Default: returns `None`, callers must check before
    /// downcasting. Implementations: `fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> { Some(self) }`.
    fn as_any_mut(&mut self) -> Option<&mut dyn std::any::Any> {
        None
    }

    /// Human-readable engine name (e.g. "global", "token", "compute", "hypergraph").
    fn get_name(&self) -> &str;

    /// Validate a message before processing.
    fn validate_message(
        &self,
        frame_number: u64,
        address: &[u8],
        message: &[u8],
    ) -> Result<()>;

    /// Process a message against current state.
    fn process_message(
        &self,
        frame_number: u64,
        fee_multiplier: &BigInt,
        address: &[u8],
        message: &[u8],
    ) -> Result<ProcessMessageResult>;

    /// Produce a proof for a message.
    fn prove(
        &self,
        domain: &[u8],
        frame_number: u64,
        message: &[u8],
    ) -> Result<proto::global::MessageRequest>;

    /// Lock addresses for cross-shard transaction processing.
    fn lock(
        &self,
        frame_number: u64,
        address: &[u8],
        message: &[u8],
    ) -> Result<Vec<Vec<u8>>>;

    /// Release any locks held by the engine.
    fn unlock(&self) -> Result<()>;

    /// Estimate the cost of processing a message.
    fn get_cost(&self, message: &[u8]) -> Result<BigInt>;

    /// Capabilities advertised by this engine.
    fn get_capabilities(&self) -> Vec<proto::node::Capability>;
}

/// Circuit compiler interface for compute intrinsics. The actual QCL
/// compiler implementation is separate -- this trait defines the boundary.
pub trait CircuitCompiler: Send + Sync {
    /// Compile QCL source code into a circuit.
    fn compile(&self, source: &str, input_sizes: &[Vec<i32>]) -> Result<Vec<u8>>;

    /// Validate a compiled circuit from bytes.
    fn validate_circuit(&self, circuit: &[u8]) -> Result<()>;
}
