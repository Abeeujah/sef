//! [`BlockVerifier`] for superblock-mode decoding against trusted headers.

use bitcoin::consensus::deserialize_partial;

use super::{BlockVerifier, VerifyError};

/// SeF-secure [`BlockVerifier`] for superblock-mode decoding.
///
/// Verifies recovered superblock singletons against trusted block headers from
/// an independently obtained header chain, matching the SeF paper's §3.2.3
/// adverserial model.Each superblock contains consecutive whole Bitcoin blocks;
/// verification parses them sequentially and validates every block's header
/// hash AND recomputed Merkle root against the corresponding trusted header.
///
/// This prevents error propagation from murky (maliciously formed) droplets
/// during peeling - the core security property of the SeF architecture.
pub struct BitcoinSuperblockVerifier<'a> {
    /// Trusted block headers from the independently obtained header chain,
    /// indexed by block position within the epoch.
    pub trusted_headers: &'a [bitcoin::block::Header],

    /// Maps superblock index -> range of block indices within the epoch.
    /// `ranges[i]` gives the block indices contained in superblock `i`.
    pub ranges: &'a [std::ops::Range<usize>],
}

impl BlockVerifier for BitcoinSuperblockVerifier<'_> {
    fn verify_and_len(&self, block_idx: u32, candidate: &[u8]) -> Result<usize, VerifyError> {
        let range = self.ranges.get(block_idx as usize).ok_or_else(|| {
            VerifyError::Deserialize(format!("superblock index {} out of range", block_idx))
        })?;

        let mut offset = 0;
        for bi in range.clone() {
            let (block, used): (bitcoin::Block, usize) = deserialize_partial(&candidate[offset..])
                .map_err(|e| {
                    VerifyError::Deserialize(format!(
                        "superblock {}, block {}: {}",
                        block_idx, bi, e
                    ))
                })?;

            let expected = self.trusted_headers.get(bi).ok_or_else(|| {
                VerifyError::Deserialize(format!("block index {} out of range", bi))
            })?;

            if block.block_hash() != expected.block_hash() {
                return Err(VerifyError::HashMismatch {
                    block_idx: bi as u32,
                    expected: expected.block_hash().to_string(),
                    got: block.block_hash().to_string(),
                });
            }

            let computed_root = block.compute_merkle_root();
            match computed_root {
                Some(root) if root == expected.merkle_root => {}
                _ => {
                    return Err(VerifyError::MerkleMismatch {
                        block_idx: bi as u32,
                        expected: expected.merkle_root.to_string(),
                        got: computed_root.map_or("(empty block)".into(), |r| r.to_string()),
                    });
                }
            }

            offset += used;
        }

        if candidate[offset..].iter().any(|&b| b != 0) {
            return Err(VerifyError::NonZeroPadding);
        }

        Ok(offset)
    }
}
