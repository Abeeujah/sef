use std::io;

/// Error type for chain operations.
#[derive(Debug)]
pub enum ChainError {
    Io(io::Error),
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
