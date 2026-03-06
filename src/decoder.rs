use std::{
    collections::{HashMap, VecDeque},
    fmt,
};

use bitcoin::consensus::deserialize_partial;

use crate::{droplet::Droplet, xor};

/// Result of a "peeling" decoding attempt.
///
/// This provides a summary of the graph reduction process, regardless
/// of whether the full source data was successfully recovered.
#[derive(Debug, Clone)]
pub struct PeelResult {
    /// Number of source blocks successfully recovered.
    pub decoded: usize,

    /// Total number of source blocks ($K$) in the epoch.
    pub total: usize,

    /// Number of "peeling" steps performed (one iteration per processed singleton).
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
            if degree[ref_di] == 1 {
                if let Some(&surviving) = droplets[ref_di].iter().find(|&&x| !decoded[x as usize]) {
                    last_block[ref_di] = surviving;
                    queue.push_back(ref_di);
                }
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

/// Errors for validating recovered source blocks.
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
    /// # Returns
    /// - `Ok(length)`: The integrity check passed; returns the size of the
    ///    actual data (excluding any trailing zero-padding).
    /// - `Err(VerifyError)`: The data is corrupted or does not match the
    ///    expected block for this index.
    fn verify_and_len(&self, block_idx: u32, candidate: &[u8]) -> Result<usize, VerifyError>;
}

/// A Bitcoin-specific implementation of `BlockVerifier`.
///
/// This verifier uses a pre-calculated list of block hashes (e.g., from
/// a trusted header chain) to validate the results of the XOR-peeling
/// process for each source block in the epoch.
pub struct BitcoinBlockVerifier {
    /// Expected `BlockHash`es where `expected_hashes[i]` is the
    /// target hash for the source block at index `i`.
    pub expected_hashes: Vec<bitcoin::BlockHash>,
}

impl BlockVerifier for BitcoinBlockVerifier {
    fn verify_and_len(&self, block_idx: u32, candidate: &[u8]) -> Result<usize, VerifyError> {
        let (block, used): (bitcoin::Block, usize) =
            deserialize_partial(candidate).map_err(|e| VerifyError::Deserialize(e.to_string()))?;

        let hash = block.block_hash();
        let expected = &self.expected_hashes[block_idx as usize];

        if hash != *expected {
            return Err(VerifyError::HashMismatch {
                block_idx,
                expected: expected.to_string(),
                got: hash.to_string(),
            });
        }

        Ok(used)
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

    /// The "residual degree" of this block.
    ///
    /// Represents how many un-peeled droplets still depend on this block.
    /// If this is 0, the block was never included in any droplet.
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

    /// Number of droplets that were rejected by the `BlockVerifier`.
    /// A non-zero value suggests network corruption or an adverserial sender.
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
        self.decoded_count == self.k
    }
}

/// Executes the Luby Transform (LT) peeling algorithm with integrated
/// payload recovery and data verification.
///
/// This function iteratively identifies "singleton" droplets, verifies their
/// content via the provided `BlockVerifier` and peels them out of all
/// connected droplets in the encoding graph.
///
/// # Logic
/// 1. Initialize the "Ripple" (queue) with all degree-1 droplets.
/// 2. For each singleton, recover the source block and verify its hash/structure.
/// 3. If verified, XOR this block out of all other droplets that include it.
/// 4. Add any newly created singletons to the queue.
/// 5. Repeat until the ripple is empty or all $K$ blocks are recovered.
pub fn peeling_decode(
    k: usize,
    droplets: Vec<Droplet>,
    verifier: &dyn BlockVerifier,
) -> DecodeResult {
    let n = droplets.len();

    // Split droplets into indices and payloads for in-place mutation
    let mut droplet_indices: Vec<Vec<u32>> = Vec::with_capacity(n);
    let mut droplet_payloads: Vec<Vec<u8>> = Vec::with_capacity(n);
    let mut droplet_disabled: Vec<bool> = vec![false; n];

    for d in droplets {
        droplet_indices.push(d.indices);
        droplet_payloads.push(d.payload);
    }

    // Block index -> list of droplet indices that reference it
    let mut block_to_droplets: HashMap<u32, Vec<usize>> = HashMap::new();
    for (di, indices) in droplet_indices.iter().enumerate() {
        for &idx in indices {
            block_to_droplets.entry(idx).or_default().push(di);
        }
    }

    // Queue of singleton droplets
    let mut queue: VecDeque<usize> = VecDeque::new();
    for (di, indices) in droplet_indices.iter().enumerate() {
        if indices.len() == 1 {
            queue.push_back(di);
        }
    }

    let mut decoded: Vec<Option<Vec<u8>>> = (0..k).map(|_| None).collect();
    let mut decoded_count = 0usize;
    let mut iterations = 0usize;
    let mut verify_failures = 0usize;

    while let Some(di) = queue.pop_front() {
        if droplet_disabled[di] || droplet_indices[di].len() != 1 {
            continue;
        }

        let block_idx = droplet_indices[di][0];
        if decoded[block_idx as usize].is_some() {
            continue;
        }

        // Take the payload
        let candidate = std::mem::take(&mut droplet_payloads[di]);

        // Verify and determine true block length
        match verifier.verify_and_len(block_idx, &candidate) {
            Ok(true_len) => {
                let block_bytes = candidate[..true_len].to_vec();
                decoded[block_idx as usize] = Some(block_bytes.clone());
                decoded_count += 1;
                iterations += 1;

                if decoded_count == k {
                    break;
                }

                // Peel: XOR recovered block out of all droplets that reference it
                if let Some(referencing) = block_to_droplets.remove(&block_idx) {
                    for ref_di in referencing {
                        if ref_di == di || droplet_disabled[ref_di] {
                            continue;
                        }
                        // XOR the block bytes into the droplet payload
                        // The block_bytes may be shorter than the payload (adaptive padding)
                        xor::xor_into(&mut droplet_payloads[ref_di], &block_bytes);

                        // Remove this block index from the droplet
                        droplet_indices[ref_di].retain(|&x| x != block_idx);

                        // If it became a singleton, add to queue
                        if droplet_indices[ref_di].len() == 1 {
                            queue.push_back(ref_di);
                        }
                    }
                }
            }
            Err(_e) => {
                // Verification failed - disable this droplet and continue
                droplet_disabled[di] = true;
                verify_failures += 1;
                // Put the payload back in case another droplet can solve this block
                droplet_payloads[di] = candidate;
            }
        }
    }

    let mut failures = Vec::new();
    for i in 0..k {
        if decoded[i].is_none() {
            let referenced_by = block_to_droplets
                .get(&(i as u32))
                .map(|v| v.iter().filter(|&&di| !droplet_disabled[di]).count())
                .unwrap_or(0);
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
    use crate::xor::xor_bytes;

    use super::*;

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
}
