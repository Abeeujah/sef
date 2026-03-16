//! [`BlockVerifier`] for symbol-mode decoding against a SHA-256 hash manifest.

use sha2::{Digest, Sha256};

use super::{BlockVerifier, VerifyError};

/// [`BlockVerifier`] for symbol-mode decoding.
///
/// Verifies fixed-size symbols against a pre-computed SHA-256 hash manifest
/// (see [`SymbolManifest`](crate::symbol::SymbolManifest)).  Each candidate
/// is hashed and compared to `symbol_hashes[block_idx]`.
pub struct SymbolVerifier<'a> {
    /// Expected byte length of every symbol.
    pub symbol_size: usize,
    /// SHA-256 digests indexed by source block position.
    pub symbol_hashes: &'a [[u8; 32]],
}

impl BlockVerifier for SymbolVerifier<'_> {
    fn verify_and_len(&self, block_idx: u32, candidate: &[u8]) -> Result<usize, VerifyError> {
        let expected = self.symbol_hashes.get(block_idx as usize).ok_or_else(|| {
            VerifyError::Deserialize(format!("symbol index {} out of range", block_idx))
        })?;

        let got: [u8; 32] = Sha256::new().chain_update(candidate).finalize().into();
        if got != *expected {
            return Err(VerifyError::HashMismatch {
                block_idx,
                expected: expected
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<String>(),
                got: got.iter().map(|b| format!("{:02x}", b)).collect::<String>(),
            });
        }

        if candidate.len() != self.symbol_size {
            return Err(VerifyError::Deserialize(format!(
                "symbol {} has length {}, expected {}",
                block_idx,
                candidate.len(),
                self.symbol_size
            )));
        }

        Ok(self.symbol_size)
    }
}
