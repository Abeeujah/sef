//! [`BlockVerifier`] for raw-block-mode decoding against trusted headers.

use bitcoin::consensus::deserialize_partial;

use super::{BlockVerifier, VerifyError};

/// SeF-secure [`BlockVerifier`] for raw-block-mode decoding.
///
/// Verifies recovered singletons against trusted block headers from an
/// independently obtained header chain, matching the SeF paper's §3.2.3
/// adverserial model. Each recovered block is validated by:
///
/// 1. Parsing the candidate as a `bitcoin::Block`
/// 2. Checking its header matches the trusted header (hash comparison)
/// 3. Recomputing the Merkle root from recovered transactions
/// 4. Verifying the recomputed root matches the header's `merkle_root`
///
/// This prevents both header-only and payload-only forgeries from
/// propagating through the peeling decoder.
pub struct BitcoinBlockVerifier {
    /// Trusted block headers, ordered by source block index within the epoch.
    /// Obtained independently from the header chain (e.g., SPV, full node).
    pub trusted_headers: Vec<bitcoin::block::Header>,
}

impl BlockVerifier for BitcoinBlockVerifier {
    fn verify_and_len(&self, block_idx: u32, candidate: &[u8]) -> Result<usize, VerifyError> {
        let (block, used): (bitcoin::Block, usize) =
            deserialize_partial(candidate).map_err(|e| VerifyError::Deserialize(e.to_string()))?;

        let expected = &self.trusted_headers[block_idx as usize];

        // §3.2.3: Check header hash against trusted header chain
        if block.block_hash() != expected.block_hash() {
            return Err(VerifyError::HashMismatch {
                block_idx,
                expected: expected.block_hash().to_string(),
                got: block.block_hash().to_string(),
            });
        }

        // §3.2.3: Recompute Merkle root from recovered transactions
        let computed_root = block.compute_merkle_root();
        let expected_root = expected.merkle_root;
        match computed_root {
            Some(root) if root == expected_root => {}
            _ => {
                return Err(VerifyError::MerkleMismatch {
                    block_idx,
                    expected: expected_root.to_string(),
                    got: computed_root.map_or("(empty block)".into(), |r| r.to_string()),
                });
            }
        }

        if candidate[used..].iter().any(|&b| b != 0) {
            return Err(VerifyError::NonZeroPadding);
        }

        Ok(used)
    }
}
