//! Core streaming abstractions for block ingestion and epoch grouping.
//!
//! The [`BlockSource`] trait decouples the fountain encoder from the specific
//! Bitcoin data-directory format, enabling both raw `blk*.dat` and
//! kernel-based backends to supply blocks through a uniform streaming
//! interface.
//!
//! [`for_each_epoch`] implements a sliding-window epoch grouper with a
//! configurable buffer exclusion for recent blocks, keeping peak memory at
//! *O*(*k* + *buffer*).

use std::{collections::VecDeque, ops::ControlFlow};

use crate::chain::error::ChainError;

/// Minimal representation of a Bitcoin block needed by the fountain encoder.
///
/// Carries the block's position in the active chain, its hash, and the full
/// consensus-serialized byte payload in [`data`](Self::data). Instances are
/// produced by [`BlockSource`] implementations and consumed by the epoch
/// grouping functions.
#[derive(Debug, Clone)]
pub struct RawBlock {
    /// Position in the active chain (genesis = 0).
    pub height: u32,

    /// Block hash as a hex-encoded string.
    pub hash: String,

    /// Full consensus-serialized block bytes.
    pub data: Vec<u8>,
}

/// A complete batch of blocks ready for fountain encoding.
///
/// Emitted by [`for_each_epoch`] and consumed by the encoder. Each batch
/// contains exactly *K* blocks, except for the last epoch which may be
/// smaller (a "tail epoch").
pub struct EpochBatch {
    /// Zero-based epoch index.
    pub index: usize,

    /// The blocks in this epoch (at most *K* blocks).
    pub blocks: Vec<RawBlock>,
}

/// Summary statistics collected via a single streaming pass over a
/// [`BlockSource`].
///
/// Captures aggregate metrics (block count, byte totals, size extremes)
/// and the tip of the active chain without retaining any block data.
pub struct ChainStats {
    pub block_count: u32,
    pub total_bytes: u64,
    pub min_block_size: usize,
    pub max_block_size: usize,
    pub tip_height: u32,
    pub tip_hash: String,
}

/// Streaming block access from a Bitcoin data source.
///
/// Implementations yield blocks one at a time via a visitor callback,
/// enabling *O*(*epoch_size*) memory usage instead of loading the entire
/// chain. The two provided implementations are
/// [`BlkFileReader`](super::blk_file_reader::BlkFileReader) and
/// [`KernelBlockReader`](super::kernel_reader::KernelBlockReader).
pub trait BlockSource {
    /// Iterates the active chain in height order, invoking `visitor` once
    /// per block.
    ///
    /// The visitor may return [`ControlFlow::Break()`] to terminate the
    /// scan early.
    ///
    /// # Errors
    ///
    /// Returns [`ChainError`] if a block cannot be read or deserialized.
    fn for_each_block(
        &self,
        visitor: &mut dyn FnMut(RawBlock) -> Result<ControlFlow<()>, ChainError>,
    ) -> Result<(), ChainError>;

    /// Collects [`ChainStats`] via a single streaming pass, without
    /// retaining any block data in memory.
    fn chain_stats(&self) -> Result<ChainStats, ChainError> {
        let mut count = 0;
        let mut total_bytes = 0;
        let mut min_size = usize::MAX;
        let mut max_size = 0;
        let mut tip_height = 0;
        let mut tip_hash = String::new();

        self.for_each_block(&mut |b| {
            let len = b.data.len();
            count += 1;
            total_bytes += len as u64;
            if len < min_size {
                min_size = len;
            }
            if len > max_size {
                max_size = len;
            }
            tip_height = b.height;
            tip_hash.clear();
            tip_hash.push_str(&b.hash);
            Ok(ControlFlow::Continue(()))
        })?;
        if count == 0 {
            min_size = 0;
        }

        Ok(ChainStats {
            block_count: count,
            total_bytes,
            min_block_size: min_size,
            max_block_size: max_size,
            tip_height,
            tip_hash,
        })
    }
}

/// Streams blocks through an epoch-grouping pipeline.
///
/// Invokes `visitor` once per epoch of `k` blocks. The most recent `buffer`
/// blocks are held back and never emitted, simulating a confirmation window
/// that prevents encoding of not-yet-settled chain tip blocks. The last
/// emitted epoch may contain fewer than `k` blocks (a "tail epoch").
///
/// Peak memory usage is *O*(*k* + *buffer*).
pub fn for_each_epoch<S: BlockSource + ?Sized>(
    source: &S,
    k: usize,
    buffer: usize,
    visitor: &mut dyn FnMut(EpochBatch) -> Result<ControlFlow<()>, ChainError>,
) -> Result<(), ChainError> {
    let mut tail: VecDeque<RawBlock> = VecDeque::with_capacity(buffer + 1);
    let mut current_epoch: Vec<RawBlock> = Vec::with_capacity(k);
    let mut epoch_idx = 0;
    let mut stopped = false;

    source.for_each_block(&mut |block| {
        if stopped {
            return Ok(ControlFlow::Break(()));
        }
        tail.push_back(block);

        while tail.len() > buffer {
            let ready = tail.pop_front().unwrap();
            current_epoch.push(ready);

            if current_epoch.len() == k {
                let batch = EpochBatch {
                    index: epoch_idx,
                    blocks: std::mem::replace(&mut current_epoch, Vec::with_capacity(k)),
                };
                epoch_idx += 1;
                if let ControlFlow::Break(()) = visitor(batch)? {
                    stopped = true;
                    return Ok(ControlFlow::Break(()));
                }
            }
        }
        Ok(ControlFlow::Continue(()))
    })?;

    if !current_epoch.is_empty() && !stopped {
        let batch = EpochBatch {
            index: epoch_idx,
            blocks: current_epoch,
        };
        let _ = visitor(batch)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_for_each_epoch_basic() {
        // Simulate a BlockSource from in-memory blocks
        struct MemSource(Vec<RawBlock>);
        impl BlockSource for MemSource {
            fn for_each_block(
                &self,
                visitor: &mut dyn FnMut(RawBlock) -> Result<ControlFlow<()>, ChainError>,
            ) -> Result<(), ChainError> {
                for b in &self.0 {
                    if let ControlFlow::Break(()) = visitor(b.clone())? {
                        break;
                    }
                }
                Ok(())
            }
        }

        let blocks: Vec<RawBlock> = (0..25)
            .map(|i| RawBlock {
                height: i,
                hash: format!("hash_{}", i),
                data: vec![i as u8; 10],
            })
            .collect();

        let source = MemSource(blocks);
        let mut epoch_indices = Vec::new();
        let mut epoch_sizes = Vec::new();

        for_each_epoch(&source, 10, 5, &mut |batch| {
            epoch_indices.push(batch.index);
            epoch_sizes.push(batch.blocks.len());
            Ok(ControlFlow::Continue(()))
        })
        .unwrap();

        // 25 blocks, buffer=5 → 20 encodable → 2 full epochs of 10
        assert_eq!(epoch_indices, vec![0, 1]);
        assert_eq!(epoch_sizes, vec![10, 10]);
    }

    #[test]
    fn test_for_each_epoch_with_tail() {
        struct MemSource(Vec<RawBlock>);
        impl BlockSource for MemSource {
            fn for_each_block(
                &self,
                visitor: &mut dyn FnMut(RawBlock) -> Result<ControlFlow<()>, ChainError>,
            ) -> Result<(), ChainError> {
                for b in &self.0 {
                    if let ControlFlow::Break(()) = visitor(b.clone())? {
                        break;
                    }
                }
                Ok(())
            }
        }

        let blocks: Vec<RawBlock> = (0..100)
            .map(|i| RawBlock {
                height: i,
                hash: format!("hash_{}", i),
                data: vec![i as u8; 10],
            })
            .collect();

        let source = MemSource(blocks);
        let mut epoch_sizes = Vec::new();

        for_each_epoch(&source, 10, 5, &mut |batch| {
            epoch_sizes.push(batch.blocks.len());
            Ok(ControlFlow::Continue(()))
        })
        .unwrap();

        // 100 blocks, buffer=5 → 95 encodable → 9 full + 1 tail of 5
        assert_eq!(epoch_sizes.len(), 10);
        assert_eq!(epoch_sizes[9], 5);
    }

    #[test]
    fn test_for_each_epoch_early_stop() {
        struct MemSource(Vec<RawBlock>);
        impl BlockSource for MemSource {
            fn for_each_block(
                &self,
                visitor: &mut dyn FnMut(RawBlock) -> Result<ControlFlow<()>, ChainError>,
            ) -> Result<(), ChainError> {
                for b in &self.0 {
                    if let ControlFlow::Break(()) = visitor(b.clone())? {
                        break;
                    }
                }
                Ok(())
            }
        }

        let blocks: Vec<RawBlock> = (0..100)
            .map(|i| RawBlock {
                height: i,
                hash: format!("hash_{}", i),
                data: vec![i as u8; 10],
            })
            .collect();

        let source = MemSource(blocks);
        let mut epoch_count = 0;

        for_each_epoch(&source, 10, 0, &mut |_batch| {
            epoch_count += 1;
            if epoch_count >= 2 {
                Ok(ControlFlow::Break(()))
            } else {
                Ok(ControlFlow::Continue(()))
            }
        })
        .unwrap();

        assert_eq!(epoch_count, 2);
    }

    #[test]
    fn test_chain_stats() {
        struct MemSource(Vec<RawBlock>);
        impl BlockSource for MemSource {
            fn for_each_block(
                &self,
                visitor: &mut dyn FnMut(RawBlock) -> Result<ControlFlow<()>, ChainError>,
            ) -> Result<(), ChainError> {
                for b in &self.0 {
                    if let ControlFlow::Break(()) = visitor(b.clone())? {
                        break;
                    }
                }
                Ok(())
            }
        }

        let blocks: Vec<RawBlock> = (0..10)
            .map(|i| RawBlock {
                height: i,
                hash: format!("hash_{}", i),
                data: vec![0u8; (i as usize + 1) * 100],
            })
            .collect();

        let source = MemSource(blocks);
        let stats = source.chain_stats().unwrap();
        assert_eq!(stats.block_count, 10);
        assert_eq!(stats.min_block_size, 100);
        assert_eq!(stats.max_block_size, 1000);
        assert_eq!(stats.tip_height, 9);
    }
}
