//! Backend for reading blocks via the `bitcoinkernel` C library FFI.
//!
//! Provides validated, index-ordered block access without manual
//! chain-ordering. Requires the `kernel` feature flag (enabled by default).

use std::{ops::ControlFlow, path::Path};

use bitcoinkernel::{ChainType, ChainstateManager, Context, Log, Logger};

use crate::chain::stream::{BlockSource, RawBlock};

struct QuietLog;

impl Log for QuietLog {
    fn log(&self, _message: &str) {}
}

/// Reads blocks from a Bitcoin Core data directory using the `bitcoinkernel`
/// library, wrapping [`ChainstateManager`] to stream blocks one at a time
/// with *O*(1) memory per block.
pub struct KernelBlockReader {
    data_dir: String,
    blocks_dir: String,
    chain_type: ChainType,
}

impl KernelBlockReader {
    /// Creates a new reader pointing at the given data directory.
    ///
    /// `data_dir` is the chain-specific data directory
    /// (e.g., `~/.bitcoin/signet`).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use std::path::Path;
    /// use bitcoinkernel::ChainType;
    /// use sef::chain::KernelBlockReader;
    ///
    /// let reader = KernelBlockReader::new(
    ///     Path::new("/home/user/.bitcoin/signet"),
    ///     ChainType::Signet,
    /// );
    /// ```
    pub fn new(data_dir: &Path, chain_type: ChainType) -> Self {
        let data = data_dir.to_string_lossy().into_owned();
        let blocks = data_dir.join("blocks").to_string_lossy().into_owned();
        Self {
            data_dir: data,
            blocks_dir: blocks,
            chain_type,
        }
    }
}

/// Initializes a [`ChainstateManager`], imports blocks from disk, then
/// iterates the active chain in height order, yielding one [`RawBlock`] per
/// call to the visitor.
impl BlockSource for KernelBlockReader {
    fn for_each_block(
        &self,
        visitor: &mut dyn FnMut(
            super::stream::RawBlock,
        )
            -> Result<std::ops::ControlFlow<()>, super::error::ChainError>,
    ) -> Result<(), super::error::ChainError> {
        let _logger = Logger::new(QuietLog)?;
        let context = Context::builder().chain_type(self.chain_type).build()?;
        let chainman = ChainstateManager::new(&context, &self.data_dir, &self.blocks_dir)?;
        chainman.import_blocks()?;

        let chain = chainman.active_chain();
        for entry in chain.iter() {
            let block = chainman.read_block_data(&entry)?;
            let data: Vec<u8> = block.consensus_encode()?;
            let hash = entry.block_hash().to_string();

            let raw = RawBlock {
                height: entry.height() as u32,
                hash,
                data,
            };

            if let ControlFlow::Break(()) = visitor(raw)? {
                break;
            }
        }

        Ok(())
    }
}
