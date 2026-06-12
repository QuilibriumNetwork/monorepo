//! Onion routing transport — provides private messaging between nodes
//! via multi-hop encrypted circuits.
//!
//! The underlying encryption uses Double/Triple Ratchet from the
//! `channel` crate and X448 key agreement from `ed448-goldilocks-plus`.

pub mod router;
pub mod relay;

/// Onion cell types matching Go's `onion/constants.go`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellType {
    /// Circuit establishment: create a new hop.
    Create = 1,
    /// Circuit established acknowledgment.
    Created = 2,
    /// Relay data cell (encrypted payload).
    Relay = 3,
    /// Destroy a circuit.
    Destroy = 4,
}

/// Maximum cell payload size (matching Go).
pub const MAX_CELL_SIZE: usize = 65536;

/// Circuit identifier.
pub type CircuitId = u32;
