use std::{collections::VecDeque, ops::ControlFlow};

use crate::chain::error::ChainError;

/// A source symbol for the fountain encoder, representing a
/// raw block read from disk: height, hash and consensus-serialized
/// bytes.
#[derive(Debug, Clone)]
pub struct RawBlock {
    /// The block height. (position in the active chain, starting from 0).
    pub height: u32,

    /// Block hash as hex string.
    pub hash: String,

    /// Raw consensus-serialized block bytes.
    pub data: Vec<u8>,
}

/// A batch of blocks forming one epoch, emitted by `for_each_epoch`.
pub struct EpochBatch {
    /// Zero-based epoch index.
    pub index: usize,

    /// The blocks in this epoch (at most `k` blocks).
    pub blocks: Vec<RawBlock>,
}

/// Chain statistics collected during a streaming scan.
pub struct ChainStats {
    pub block_count: u32,
    pub total_bytes: u64,
    pub min_block_size: usize,
    pub max_block_size: usize,
    pub tip_height: u32,
    pub tip_hash: String,
}

/// Trait for streaming block access.
///
/// Implementations yield blocks one at a time via a callback, enabling
/// O(epoch_size) memory usage instead of loading the entire chain.
pub trait BlockSource {
    /// Visit each block on the active chain in height order.
    ///
    /// The visitor receives one `RawBlock` at a time. Return
    /// `ControlFlow::Break(())` to stop early.
    fn for_each_block(
        &self,
        visitor: &mut dyn FnMut(RawBlock) -> Result<ControlFlow<()>, ChainError>,
    ) -> Result<(), ChainError>;

    /// Convenience: load all blocks into memory (test/compat path).
    fn read_all_blocks(&self) -> Result<Vec<RawBlock>, ChainError> {
        let mut out = Vec::new();
        self.for_each_block(&mut |b| {
            out.push(b);
            Ok(ControlFlow::Continue(()))
        })?;
        Ok(out)
    }

    /// Collect chain statistics without retaining block data.
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

/// Stream blocks through an epoch-grouping pipeline.
///
/// Calls `visitor` once per complete epoch of `k` blocks. The most recent
/// `buffer` blocks are excluded. Peak memory is O(k + buffer).
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

/// Group blocks into epochs of size `k`.
///
/// The last epoch may be smaller than `k` (a "tail epoch").
/// The most recent `buffer` blocks are excluded from encoding.
///
/// NOTE: this function requires all blocks in memory. Prefer
/// `for_each_epoch()` for streaming epoch processing.
pub fn group_into_epochs(blocks: &[RawBlock], k: usize, buffer: usize) -> Vec<&[RawBlock]> {
    if blocks.len() <= buffer {
        return vec![];
    }

    let encodable = &blocks[..blocks.len() - buffer];
    encodable.chunks(k).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_into_epochs() {
        let blocks: Vec<RawBlock> = (0..100)
            .map(|i| RawBlock {
                height: i,
                hash: format!("hash_{}", i),
                data: vec![i as u8; 10],
            })
            .collect();

        // k=10, buffer=5 -> 95 encodable blocks -> 9 full epochs + 1 tail of 5
        let epochs = group_into_epochs(&blocks, 10, 5);
        assert_eq!(epochs.len(), 10);
        assert_eq!(epochs[0].len(), 10);
        assert_eq!(epochs[0][0].height, 0);
        assert_eq!(epochs[9].len(), 5);
        assert_eq!(epochs[9][0].height, 90);
    }

    #[test]
    fn test_group_into_epochs_all_buffer() {
        let blocks: Vec<RawBlock> = (0..10)
            .map(|i| RawBlock {
                height: i,
                hash: format!("hash_{}", i),
                data: vec![i as u8; 10],
            })
            .collect();

        let epochs = group_into_epochs(&blocks, 5, 20);
        assert!(epochs.is_empty());
    }

    #[test]
    fn test_group_into_epochs_no_buffer() {
        let blocks: Vec<RawBlock> = (0..25)
            .map(|i| RawBlock {
                height: i,
                hash: format!("hash_{}", i),
                data: vec![i as u8; 10],
            })
            .collect();

        let epochs = group_into_epochs(&blocks, 10, 0);
        assert_eq!(epochs.len(), 3);
        assert_eq!(epochs[2].len(), 5);
    }

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
