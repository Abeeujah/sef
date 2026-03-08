//! Unified error type for chain ingestion operations.
//!
//! [`ChainError`] wraps I/O errors, block-parsing failures, and (with the
//! `kernel` feature) [`bitcoinkernel`] errors into a single `Result`-compatible
//! type used throughout the [`chain`](super) module.

use std::io;

/// Unified error type for all [`chain`](super) ingestion operations.
///
/// Each variant captures a distinct failure mode encountered while reading
/// blocks from disk or via the kernel FFI.
#[derive(Debug)]
pub enum ChainError {
    /// An I/O error propagated from filesystem operations (e.g., opening
    /// `blk*.dat` files or reading `xor.dat`).
    Io(io::Error),
    /// A block deserialization or chain-ordering failure (e.g., an invalid
    /// consensus-serialized header or a missing genesis block).
    Parse(String),
    #[cfg(feature = "kernel")]
    Kernel(bitcoinkernel::KernelError),
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainError::Io(e) => write!(f, "I/O error: {}", e),
            ChainError::Parse(e) => write!(f, "parse error: {}", e),
            #[cfg(feature = "kernel")]
            ChainError::Kernel(e) => write!(f, "kernel error: {}", e),
        }
    }
}

impl std::error::Error for ChainError {}

impl From<io::Error> for ChainError {
    fn from(value: io::Error) -> Self {
        ChainError::Io(value)
    }
}

#[cfg(feature = "kernel")]
impl From<bitcoinkernel::KernelError> for ChainError {
    fn from(value: bitcoinkernel::KernelError) -> Self {
        ChainError::Kernel(value)
    }
}
