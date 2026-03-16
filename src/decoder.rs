//! LT peeling decoder and block verification infrastructure.
//!
//! The peeling decoder operates on the bipartite graph between droplets and
//! source blocks, iteratively resolving singletons (degree-1 droplets) to
//! recover source data.  Two entry points are provided:
//!
//! - [`peeling_check`] — lightweight graph-only simulation (no payloads).
//! - [`peeling_decode`] — full payload-recovery decoder with integrated
//!   [`BlockVerifier`] verification.
//!
//! Verification is pluggable via the [`BlockVerifier`] trait, with concrete
//! implementations for Bitcoin blocks ([`BitcoinBlockVerifier`]),
//! superblock-mode decoding ([`BitcoinSuperblockVerifier`]), and
//! symbol-mode decoding ([`SymbolVerifier`]).
//!
//! # Dependency graph
//!
//! - **Depends on:** [`crate::droplet`], [`crate::xor`]

use std::{collections::VecDeque, fmt};

use bitcoin::consensus::deserialize_partial;
use sha2::{Digest, Sha256};

use crate::{droplet::Droplet, xor};

/// Result of a "peeling" decoding attempt.
///
/// This provides a summary of the graph reduction process, regardless
/// of whether the full source data was successfully recovered.
#[derive(Debug, Clone)]
pub struct PeelResult {
    /// Number of source blocks successfully recovered.
    /// Monotonically increases during the peeling process.
    pub decoded: usize,

    /// Total number of source blocks ($K$) in the epoch.
    pub total: usize,

    /// Number of peeling steps performed (one per processed singleton).
    /// Equals `decoded` in the absence of duplicate singletons.
    pub iterations: usize,

    /// Whether all `total` blocks were recovered (decoded == total).
    pub success: bool,
}

/// Simulates the Luby Transform "Peeling" decoder on the bipartite graph
/// of droplets and source blocks.
///
/// This function verifies if the current set of droplets provides enough
/// information to recover all $K$ source blocks. It uses a queue-based
/// approach to track the "Ripple" (available singletons).
///
/// # Examples
///
/// ```
/// use sef::decoder::peeling_check;
///
/// // Three singletons covering all blocks → success.
/// let droplets = vec![vec![0], vec![1], vec![2]];
/// let result = peeling_check(3, &droplets);
/// assert!(result.success);
///
/// // A chain that peels from a single seed singleton.
/// let droplets = vec![vec![0], vec![0, 1], vec![1, 2]];
/// let result = peeling_check(3, &droplets);
/// assert!(result.success);
/// assert_eq!(result.decoded, 3);
/// ```
pub fn peeling_check(k: usize, droplets: &[Vec<u32>]) -> PeelResult {
    let mut degree: Vec<u32> = droplets.iter().map(|d| d.len() as u32).collect();
    let mut last_block: Vec<u32> = droplets.iter().map(|d| *d.last().unwrap_or(&0)).collect();

    let mut block_to_droplets: Vec<Vec<usize>> = vec![Vec::new(); k];
    for (di, indices) in droplets.iter().enumerate() {
        for &idx in indices {
            block_to_droplets[idx as usize].push(di);
        }
    }

    let mut queue: VecDeque<usize> = VecDeque::new();
    for (di, &deg) in degree.iter().enumerate() {
        if deg == 1 {
            queue.push_back(di);
        }
    }

    let mut decoded = vec![false; k];
    let mut decoded_count = 0usize;
    let mut iterations = 0usize;

    while let Some(di) = queue.pop_front() {
        if degree[di] != 1 {
            continue;
        }
        let block_idx = last_block[di];
        if decoded[block_idx as usize] {
            continue;
        }

        decoded[block_idx as usize] = true;
        decoded_count += 1;
        iterations += 1;

        if decoded_count == k {
            break;
        }

        for ref_di in std::mem::take(&mut block_to_droplets[block_idx as usize]) {
            if ref_di == di {
                continue;
            }
            degree[ref_di] -= 1;
            if degree[ref_di] == 1
                && let Some(&surviving) = droplets[ref_di].iter().find(|&&x| !decoded[x as usize])
            {
                last_block[ref_di] = surviving;
                queue.push_back(ref_di);
            }
        }
    }

    PeelResult {
        decoded: decoded_count,
        total: k,
        iterations,
        success: decoded_count == k,
    }
}

/// Errors produced when a [`BlockVerifier`] rejects a recovered source block.
///
/// # Variants
///
/// | Variant | Meaning |
/// |---------|---------|
/// | [`Deserialize`](Self::Deserialize) | Candidate bytes cannot be parsed as the expected structure. |
/// | [`HashMismatch`](Self::HashMismatch) | Parsed successfully but the content hash does not match. |
/// | [`NonZeroPadding`](Self::NonZeroPadding) | Trailing bytes after the parsed structure are not all zero. |
#[derive(Debug)]
pub enum VerifyError {
    /// The recovered bytes are not a valid Bitcoin block structure.
    Deserialize(String),

    /// Integrity failure: the XOR-recovered block hash is incorrect.
    ///
    /// This usually indicates that one or more droplets used in the
    /// reconstruction were corrupted or malformed.
    HashMismatch {
        block_idx: u32,
        expected: String,
        got: String,
    },

    /// Integrity failure: the recomputed Merkle root from the recovered
    /// transactions does not match the trusted header's `merkle_root`.
    MerkleMismatch {
        block_idx: u32,
        expected: String,
        got: String,
    },

    /// Security/Sanity check: found non-zero data where zero-padding was expected.
    NonZeroPadding,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Deserialize(e) => write!(f, "deserialize error: {}", e),
            VerifyError::HashMismatch {
                block_idx,
                expected,
                got,
            } => write!(
                f,
                "hash mismatch for block {}: expected {}, got {}",
                block_idx, expected, got
            ),
            VerifyError::MerkleMismatch {
                block_idx,
                expected,
                got,
            } => write!(
                f,
                "merkle mismatch for block {}: expected {}, got {}",
                block_idx, expected, got
            ),
            VerifyError::NonZeroPadding => write!(f, "non-zero padding bytes"),
        }
    }
}

/// Trait for validating recovered source blocks and stripping adaptive padding.
///
/// In a Fountain Code, source blocks are XOR'd as if they were uniform in size.
/// This trait allows the application to inspect a recovered `candidate` buffer,
/// verify its integrity (e.g., via hashing), and determine the original
/// data length before it was zero-padded.
pub trait BlockVerifier {
    /// Validates the `candidate` buffer against the expected data for `block_idx`.
    ///
    /// The returned length represents the original data size *before*
    /// zero-padding was applied.  The caller uses this value to strip
    /// trailing padding from `candidate`, so implementations **must**
    /// return the exact pre-padding byte count on success.
    ///
    /// # Returns
    /// - `Ok(length)`: The integrity check passed; `length` is the byte count
    ///   of the actual data (excluding any trailing zero-padding).
    /// - `Err(VerifyError)`: The data is corrupted or does not match the
    ///   expected block for this index.
    fn verify_and_len(&self, block_idx: u32, candidate: &[u8]) -> Result<usize, VerifyError>;
}

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

/// Represents the termination state of the peeling decoder.
#[derive(Debug, Clone, PartialEq)]
pub enum DecodeStopReason {
    /// Success: All $K$ source blocks were successfully recovered.
    Completed,

    /// Failure: The "Ripple" of degree-1 droplets is empty, but some blocks
    /// are still missing. The graph is currently unsolvable.
    Stalled,
}

/// Detailed information about a source block that remained unsolved.
#[derive(Debug, Clone)]
pub struct BlockFailure {
    /// The source block index $[0, K) that was not recovered.
    pub index: u32,

    /// Residual degree: number of un-peeled droplets still referencing this
    /// block.  A value of 0 means the block was never covered by any droplet
    /// in the input set.
    pub referenced_by: usize,
}

/// The final output of the fountain code decoding process.
///
/// This struct captures both the successfully recovered source data and
/// detailed diagnostics regarding the state of the decoding graph.
#[derive(Debug)]
pub struct DecodeResult {
    /// The reconstructed source blocks.
    /// `Some(data)` contains the verified, un-padded block bytes.
    /// `None` indicates the block remained an "unsolved" node in the graph.
    pub blocks: Vec<Option<Vec<u8>>>,

    /// Total source blocks ($K$) expected in this epoch.
    pub k: usize,

    /// Count of successfully recovered and verified blocks.
    pub decoded_count: usize,

    /// Total peeling steps performed.
    pub iterations: usize,

    /// Number of droplets rejected by the [`BlockVerifier`].
    /// A non-zero value suggests network corruption or an adversarial sender;
    /// useful as a signal for Byzantine-fault detection.
    pub verify_failures: usize,

    /// The condition that caused the decoder to terminate.
    pub stop_reason: DecodeStopReason,

    /// A list of specific blocks that could not be recovered and their
    /// final residual degree in the graph.
    pub failures: Vec<BlockFailure>,
}

impl DecodeResult {
    /// Returns `true` if every source block in the epoch was recovered.
    pub fn is_success(&self) -> bool {
        self.decoded_count == self.k && self.stop_reason == DecodeStopReason::Completed
    }
}

/// Executes the Luby Transform (LT) peeling algorithm with integrated
/// payload recovery and data verification.
///
/// Iteratively identifies singleton droplets, verifies their content via the
/// provided [`BlockVerifier`], and peels them out of all connected droplets
/// in the encoding graph.  Droplets that fail
/// [`Droplet::validate`](crate::droplet::Droplet::validate) are silently
/// disabled before the main loop begins.
///
/// # Logic
/// 1. Initialize the "Ripple" (queue) with all degree-1 droplets.
/// 2. For each singleton, recover the source block and verify its hash/structure.
/// 3. If verified, XOR this block out of all other droplets that include it.
/// 4. Add any newly created singletons to the queue.
/// 5. Repeat until the ripple is empty or all $K$ blocks are recovered.
///
/// # Panics
///
/// This function does not panic.
///
/// # Examples
///
/// ```
/// use sef::decoder::{peeling_decode, BlockVerifier, VerifyError, DecodeStopReason};
/// use sef::droplet::Droplet;
///
/// // Trivial verifier that accepts everything at full length.
/// struct AcceptAll;
/// impl BlockVerifier for AcceptAll {
///     fn verify_and_len(&self, _idx: u32, c: &[u8]) -> Result<usize, VerifyError> {
///         Ok(c.len())
///     }
/// }
///
/// let blocks: Vec<Vec<u8>> = vec![vec![0xAA; 8], vec![0xBB; 8], vec![0xCC; 8]];
/// let droplets = vec![
///     Droplet { epoch_id: 0, droplet_id: 0, indices: vec![0],
///               padded_len: 8, payload: blocks[0].clone() },
///     Droplet { epoch_id: 0, droplet_id: 1, indices: vec![1],
///               padded_len: 8, payload: blocks[1].clone() },
///     Droplet { epoch_id: 0, droplet_id: 2, indices: vec![2],
///               padded_len: 8, payload: blocks[2].clone() },
/// ];
///
/// let result = peeling_decode(3, droplets, &AcceptAll);
/// assert!(result.is_success());
/// assert_eq!(result.stop_reason, DecodeStopReason::Completed);
/// ```
pub fn peeling_decode(
    k: usize,
    droplets: Vec<Droplet>,
    verifier: &dyn BlockVerifier,
) -> DecodeResult {
    let n = droplets.len();

    // Split droplets into degree/xor-index and payloads for in-place mutation
    let mut remaining_degree: Vec<u32> = Vec::with_capacity(n);
    let mut xor_index: Vec<u32> = Vec::with_capacity(n);
    let mut droplet_payloads: Vec<Vec<u8>> = Vec::with_capacity(n);
    let mut droplet_disabled: Vec<bool> = Vec::with_capacity(n);

    // Block index -> list of droplet indices that reference it.
    // Dense Vec since indices are in [0, k); avoids HashMap hashing overhead.
    let mut block_to_droplets: Vec<Vec<usize>> = vec![Vec::new(); k];

    for d in droplets {
        // Validate droplet structure: sorted unique indices in range, payload matches padded_len
        if d.validate(k as u32).is_err() {
            droplet_disabled.push(true);
            remaining_degree.push(0);
            xor_index.push(0);
            droplet_payloads.push(d.payload);
            continue;
        }
        droplet_disabled.push(false);
        let di = remaining_degree.len();
        let deg = d.indices.len() as u32;
        let xor = d.indices.iter().fold(0u32, |acc, &x| acc ^ x);
        for &idx in &d.indices {
            block_to_droplets[idx as usize].push(di);
        }
        remaining_degree.push(deg);
        xor_index.push(xor);
        droplet_payloads.push(d.payload);
    }

    // Queue of singleton droplets
    let mut queue: VecDeque<usize> = VecDeque::new();
    for (di, deg) in remaining_degree.iter().enumerate() {
        if *deg == 1 {
            queue.push_back(di);
        }
    }

    let mut decoded: Vec<Option<Vec<u8>>> = (0..k).map(|_| None).collect();
    let mut decoded_count = 0;
    let mut iterations = 0;
    let mut verify_failures = 0;

    while let Some(di) = queue.pop_front() {
        if droplet_disabled[di] || remaining_degree[di] != 1 {
            continue;
        }

        let block_idx = xor_index[di];
        if decoded[block_idx as usize].is_some() {
            continue;
        }

        let candidate = std::mem::take(&mut droplet_payloads[di]);
        match verifier.verify_and_len(block_idx, &candidate) {
            Ok(true_len) => {
                let mut block_bytes = candidate;
                block_bytes.truncate(true_len);
                decoded_count += 1;
                iterations += 1;

                if decoded_count == k {
                    decoded[block_idx as usize] = Some(block_bytes);
                    break;
                }

                // Peel: XOR recovered block out of all droplets that reference it
                let referencing = std::mem::take(&mut block_to_droplets[block_idx as usize]);
                {
                    for ref_di in referencing {
                        if ref_di == di || droplet_disabled[ref_di] {
                            continue;
                        }
                        // XOR the recovered block out of the droplet payload.
                        // block_bytes may be shorter (adaptive padding); must not be longer.
                        if !xor::xor_into_fixed(&mut droplet_payloads[ref_di], &block_bytes) {
                            // Recovered block is longer than residual payload — malformed droplet
                            droplet_disabled[ref_di] = true;
                            continue;
                        }

                        remaining_degree[ref_di] -= 1;
                        xor_index[ref_di] ^= block_idx;

                        if remaining_degree[ref_di] == 1 {
                            queue.push_back(ref_di);
                        }
                    }
                }

                decoded[block_idx as usize] = Some(block_bytes);
            }
            Err(_e) => {
                // Verification failed — disable this droplet and continue
                droplet_disabled[di] = true;
                verify_failures += 1;
                // Put the payload back in case another droplet can solve this block
                droplet_payloads[di] = candidate;
            }
        }
    }

    // Build failure analysis for undecoded blocks
    let mut failures = Vec::new();
    for i in 0..k {
        if decoded[i].is_none() {
            let referenced_by = block_to_droplets[i]
                .iter()
                .filter(|&&di| !droplet_disabled[di])
                .count();
            failures.push(BlockFailure {
                index: i as u32,
                referenced_by,
            });
        }
    }

    let stop_reason = if decoded_count == k {
        DecodeStopReason::Completed
    } else {
        DecodeStopReason::Stalled
    };

    DecodeResult {
        blocks: decoded,
        k,
        decoded_count,
        iterations,
        verify_failures,
        stop_reason,
        failures,
    }
}

#[cfg(test)]
mod tests {
    use crate::xor::xor_blocks;

    use super::*;

    fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
        xor_blocks(&[a, b])
    }

    #[test]
    fn test_all_singletons() {
        let droplets = vec![vec![0], vec![1], vec![2]];
        let result = peeling_check(3, &droplets);
        assert!(result.success);
        assert_eq!(result.decoded, 3);
    }

    #[test]
    fn test_simple_peeling() {
        let droplets = vec![vec![0], vec![0, 1], vec![1, 2]];
        let result = peeling_check(3, &droplets);
        assert!(result.success);
        assert_eq!(result.decoded, 3);
    }

    #[test]
    fn test_insufficient_droplets() {
        let droplets = vec![vec![0]];
        let result = peeling_check(3, &droplets);
        assert!(!result.success);
        assert_eq!(result.decoded, 1);
    }

    #[test]
    fn test_no_singletons() {
        let droplets = vec![vec![0, 1], vec![1, 2], vec![0, 2]];
        let result = peeling_check(3, &droplets);
        assert!(!result.success);
        assert_eq!(result.decoded, 0);
    }

    #[test]
    fn test_redundant_droplets() {
        let droplets = vec![vec![0], vec![1], vec![0, 1], vec![0]];
        let result = peeling_check(2, &droplets);
        assert!(result.success);
    }

    #[test]
    fn test_chain_peeling() {
        let droplets = vec![vec![0], vec![0, 1], vec![1, 2], vec![2, 3], vec![3, 4]];
        let result = peeling_check(5, &droplets);
        assert!(result.success);
        assert_eq!(result.decoded, 5);
    }

    /// A test verifier that accepts any candidate and returns its full length.
    struct AcceptAllVerifier;
    impl BlockVerifier for AcceptAllVerifier {
        fn verify_and_len(&self, _block_idx: u32, candidate: &[u8]) -> Result<usize, VerifyError> {
            Ok(candidate.len())
        }
    }

    /// A verifier that knows the expected block data and checks it.
    struct ExactVerifier {
        expected: Vec<Vec<u8>>,
    }
    impl BlockVerifier for ExactVerifier {
        fn verify_and_len(&self, block_idx: u32, candidate: &[u8]) -> Result<usize, VerifyError> {
            let expected = &self.expected[block_idx as usize];
            if candidate.len() < expected.len() {
                return Err(VerifyError::Deserialize("too short".into()));
            }
            if &candidate[..expected.len()] != expected.as_slice() {
                return Err(VerifyError::HashMismatch {
                    block_idx,
                    expected: format!("block_{}", block_idx),
                    got: "mismatch".into(),
                });
            }
            Ok(expected.len())
        }
    }

    fn make_test_blocks(k: usize) -> Vec<Vec<u8>> {
        (0..k)
            .map(|i| {
                let size = 10 + (i % 5) * 3;
                (0..size)
                    .map(|j| ((i * 32 + j * 17) & 0xFF) as u8)
                    .collect()
            })
            .collect()
    }

    #[test]
    fn test_decode_all_singletons() {
        let blocks = make_test_blocks(3);
        let droplets: Vec<Droplet> = blocks
            .iter()
            .enumerate()
            .map(|(i, b)| Droplet {
                epoch_id: 0,
                droplet_id: i as u64,
                indices: vec![i as u32],
                padded_len: b.len() as u32,
                payload: b.clone(),
            })
            .collect();

        let verifier = ExactVerifier {
            expected: blocks.clone(),
        };
        let result = peeling_decode(3, droplets, &verifier);
        assert!(result.is_success());
        assert_eq!(result.decoded_count, 3);
        for (i, block) in result.blocks.iter().enumerate() {
            assert_eq!(block.as_ref().unwrap(), &blocks[i]);
        }
    }

    #[test]
    fn test_decode_with_xor_peeling() {
        let blocks = make_test_blocks(3);
        // Droplet 0: singleton for block 0
        // Droplet 1: XOR of blocks 0 and 1
        // Droplet 2: XOR of blocks 1 and 2
        let xor_01 = xor_bytes(&blocks[0], &blocks[1]);
        let xor_12 = xor_bytes(&blocks[1], &blocks[2]);

        let droplets = vec![
            Droplet {
                epoch_id: 0,
                droplet_id: 0,
                indices: vec![0],
                padded_len: blocks[0].len() as u32,
                payload: blocks[0].clone(),
            },
            Droplet {
                epoch_id: 0,
                droplet_id: 1,
                indices: vec![0, 1],
                padded_len: xor_01.len() as u32,
                payload: xor_01,
            },
            Droplet {
                epoch_id: 0,
                droplet_id: 2,
                indices: vec![1, 2],
                padded_len: xor_12.len() as u32,
                payload: xor_12,
            },
        ];

        let verifier = ExactVerifier {
            expected: blocks.clone(),
        };
        let result = peeling_decode(3, droplets, &verifier);
        assert!(result.is_success());
        assert_eq!(result.decoded_count, 3);
        for (i, block) in result.blocks.iter().enumerate() {
            assert_eq!(block.as_ref().unwrap(), &blocks[i]);
        }
    }

    #[test]
    fn test_decode_stall() {
        let blocks = make_test_blocks(3);
        // Only degree-2 droplets, no singletons -> stall
        let xor_01 = xor_bytes(&blocks[0], &blocks[1]);
        let xor_12 = xor_bytes(&blocks[1], &blocks[2]);

        let droplets = vec![
            Droplet {
                epoch_id: 0,
                droplet_id: 0,
                indices: vec![0, 1],
                padded_len: xor_01.len() as u32,
                payload: xor_01,
            },
            Droplet {
                epoch_id: 0,
                droplet_id: 1,
                indices: vec![1, 2],
                padded_len: xor_12.len() as u32,
                payload: xor_12,
            },
        ];

        let verifier = AcceptAllVerifier;
        let result = peeling_decode(3, droplets, &verifier);
        assert!(!result.is_success());
        assert_eq!(result.stop_reason, DecodeStopReason::Stalled);
        assert_eq!(result.failures.len(), 3);
    }

    #[test]
    fn test_decode_with_padding() {
        // Block 0 is short, block 1 is long
        let blocks = vec![vec![0xAA, 0xBB], vec![0xCC, 0xDD, 0xEE, 0xFF]];

        // Singleton for block 1 (no padding needed)
        // XOR of block 0 and 1: block 0 is padded to len 4
        let padded_0 = vec![0xAA, 0xBB, 0x00, 0x00];
        let xor_01 = xor_bytes(&padded_0, &blocks[1]);

        let droplets = vec![
            Droplet {
                epoch_id: 0,
                droplet_id: 0,
                indices: vec![1],
                padded_len: 4,
                payload: blocks[1].clone(),
            },
            Droplet {
                epoch_id: 0,
                droplet_id: 1,
                indices: vec![0, 1],
                padded_len: 4,
                payload: xor_01,
            },
        ];

        // Verifier that knows true lengths
        let verifier = ExactVerifier {
            expected: blocks.clone(),
        };
        let result = peeling_decode(2, droplets, &verifier);
        assert!(result.is_success());
        // Block 0 should be recovered with correct length (2 bytes, not 4)
        assert_eq!(result.blocks[0].as_ref().unwrap(), &blocks[0]);
        assert_eq!(result.blocks[1].as_ref().unwrap(), &blocks[1]);
    }

    #[test]
    fn test_decode_failure_analysis() {
        let blocks = make_test_blocks(5);
        // Only provide singletons for blocks 0 and 1
        let droplets = vec![
            Droplet {
                epoch_id: 0,
                droplet_id: 0,
                indices: vec![0],
                padded_len: blocks[0].len() as u32,
                payload: blocks[0].clone(),
            },
            Droplet {
                epoch_id: 0,
                droplet_id: 1,
                indices: vec![1],
                padded_len: blocks[1].len() as u32,
                payload: blocks[1].clone(),
            },
        ];

        let verifier = ExactVerifier {
            expected: blocks.clone(),
        };
        let result = peeling_decode(5, droplets, &verifier);
        assert!(!result.is_success());
        assert_eq!(result.decoded_count, 2);
        assert_eq!(result.failures.len(), 3);
        // Blocks 2, 3, 4 should be in failures
        let failed_indices: Vec<u32> = result.failures.iter().map(|f| f.index).collect();
        assert_eq!(failed_indices, vec![2, 3, 4]);
    }

    #[test]
    fn test_roundtrip_encode_decode_rsd() {
        use crate::distribution::RobustSoliton;
        use crate::droplet::{Encoder, EpochParams};

        let k = 20;
        let blocks = make_test_blocks(k);
        let dist = RobustSoliton::new(k, 0.1, 0.5);
        let params = EpochParams::new(0, k as u32, [42u8; 32]);
        let encoder = Encoder::new(&params, &dist, &blocks);

        // Generate enough droplets for reliable decoding
        let droplets = encoder.generate_n(k as u64 * 5);

        let verifier = ExactVerifier {
            expected: blocks.clone(),
        };
        let result = peeling_decode(k, droplets, &verifier);
        assert!(
            result.is_success(),
            "RSD round-trip failed: decoded {}/{}",
            result.decoded_count,
            k
        );
        for (i, block) in result.blocks.iter().enumerate() {
            assert_eq!(block.as_ref().unwrap(), &blocks[i]);
        }
    }

    #[test]
    fn test_adversarial_droplet_rejected() {
        let blocks = make_test_blocks(3);
        // Provide valid singletons for blocks 1 and 2
        // Inject a corrupted singleton for block 0
        let mut corrupted = blocks[0].clone();
        corrupted[0] ^= 0xFF; // flip a byte

        let droplets = vec![
            Droplet {
                epoch_id: 0,
                droplet_id: 0,
                indices: vec![0],
                padded_len: corrupted.len() as u32,
                payload: corrupted,
            },
            Droplet {
                epoch_id: 0,
                droplet_id: 1,
                indices: vec![0],
                padded_len: blocks[0].len() as u32,
                payload: blocks[0].clone(),
            },
            Droplet {
                epoch_id: 0,
                droplet_id: 2,
                indices: vec![1],
                padded_len: blocks[1].len() as u32,
                payload: blocks[1].clone(),
            },
            Droplet {
                epoch_id: 0,
                droplet_id: 3,
                indices: vec![2],
                padded_len: blocks[2].len() as u32,
                payload: blocks[2].clone(),
            },
        ];

        let verifier = ExactVerifier {
            expected: blocks.clone(),
        };
        let result = peeling_decode(3, droplets, &verifier);
        assert!(result.is_success());
        assert!(result.verify_failures >= 1);
        for (i, block) in result.blocks.iter().enumerate() {
            assert_eq!(block.as_ref().unwrap(), &blocks[i]);
        }
    }

    #[test]
    fn test_all_verify_failures() {
        struct RejectAllVerifier;
        impl BlockVerifier for RejectAllVerifier {
            fn verify_and_len(&self, idx: u32, _candidate: &[u8]) -> Result<usize, VerifyError> {
                Err(VerifyError::HashMismatch {
                    block_idx: idx,
                    expected: "expected".into(),
                    got: "got".into(),
                })
            }
        }

        let blocks = make_test_blocks(3);
        let droplets: Vec<Droplet> = blocks
            .iter()
            .enumerate()
            .map(|(i, b)| Droplet {
                epoch_id: 0,
                droplet_id: i as u64,
                indices: vec![i as u32],
                padded_len: b.len() as u32,
                payload: b.clone(),
            })
            .collect();

        let result = peeling_decode(3, droplets, &RejectAllVerifier);
        assert!(!result.is_success());
        assert_eq!(result.decoded_count, 0);
        assert_eq!(result.verify_failures, 3);
        assert_eq!(result.stop_reason, DecodeStopReason::Stalled);
    }

    #[test]
    fn test_out_of_range_droplet_skipped() {
        let blocks = make_test_blocks(3);
        let mut droplets: Vec<Droplet> = blocks
            .iter()
            .enumerate()
            .map(|(i, b)| Droplet {
                epoch_id: 0,
                droplet_id: i as u64,
                indices: vec![i as u32],
                padded_len: b.len() as u32,
                payload: b.clone(),
            })
            .collect();
        // Add a droplet with out-of-range index
        droplets.push(Droplet {
            epoch_id: 0,
            droplet_id: 99,
            indices: vec![999],
            padded_len: 4,
            payload: vec![0; 4],
        });

        let verifier = ExactVerifier {
            expected: blocks.clone(),
        };
        let result = peeling_decode(3, droplets, &verifier);
        assert!(result.is_success());
        assert_eq!(result.decoded_count, 3);
    }

    #[test]
    fn last_block_is_not_dropped_on_completion() {
        struct AcceptAll;
        impl BlockVerifier for AcceptAll {
            fn verify_and_len(&self, _idx: u32, c: &[u8]) -> Result<usize, VerifyError> {
                Ok(c.len())
            }
        }

        // Two blocks. One degree-2 droplet + one degree-1 droplet.
        // Block 1 is only recoverable by peeling block 0 out of the degree-2 droplet,
        // making it the *last* block decoded — the case the bug hit.
        let b0 = vec![0xAAu8; 8];
        let b1 = vec![0xBBu8; 8];
        let xored: Vec<u8> = b0.iter().zip(b1.iter()).map(|(a, b)| a ^ b).collect();

        let droplets = vec![
            Droplet {
                epoch_id: 0,
                droplet_id: 0,
                indices: vec![0],
                padded_len: 8,
                payload: b0.clone(),
            },
            Droplet {
                epoch_id: 0,
                droplet_id: 1,
                indices: vec![0, 1],
                padded_len: 8,
                payload: xored,
            },
        ];

        let result = peeling_decode(2, droplets, &AcceptAll);
        assert_eq!(result.stop_reason, DecodeStopReason::Completed);
        assert_eq!(result.decoded_count, 2);
        // This is the assertion that would have failed before the fix
        assert_eq!(result.blocks[1].as_deref(), Some(b1.as_slice()));
    }
}
