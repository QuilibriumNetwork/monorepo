use num_bigint::BigInt;
use quil_types::error::Result;

/// An intrinsic is a protocol-native operation within an execution engine.
/// Each engine contains one or more intrinsics, identified by domain address.
pub trait Intrinsic: Send + Sync {
    /// The domain address this intrinsic handles.
    fn address(&self) -> &[u8];

    /// Validate an input message.
    fn validate(&self, frame_number: u64, input: &[u8]) -> Result<()>;

    /// Execute a state transition step.
    fn invoke_step(
        &self,
        frame_number: u64,
        input: &[u8],
        fee_paid: &BigInt,
        fee_multiplier: &BigInt,
    ) -> Result<Vec<u8>>;

    /// Get the cost of an operation.
    fn get_cost(&self, input: &[u8]) -> Result<BigInt>;
}
