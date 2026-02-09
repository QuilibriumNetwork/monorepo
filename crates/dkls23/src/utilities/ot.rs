//! Oblivious Transfer.
//!
//! The main protocol is given by the file [`extension`], but it needs
//! a base OT implemented in [`base`].

pub mod base;
pub mod extension;

/// Represents an error during any of the OT protocols.
#[derive(Debug, Clone)]
pub struct ErrorOT {
    pub description: String,
}

impl ErrorOT {
    /// Creates an instance of `ErrorOT`.
    #[must_use]
    pub fn new(description: &str) -> ErrorOT {
        ErrorOT {
            description: String::from(description),
        }
    }
}
