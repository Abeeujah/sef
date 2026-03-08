//! Backend for reading Bitcoin blocks directly from Bitcoin Core's `blk*.dat` files.
//!
//! Handles XOR obfuscation (introduced in Bitcoin Core v28+) by reading the
//! `xor.dat` key file from the blocks directory. Scans files in sorted order,
//! then chains blocks by `prev_blockhash` to produce canonical height ordering.
//!
//! For production use on mainnet, prefer
//! [`KernelBlockReader`](super::kernel_reader::KernelBlockReader) which uses
//! the validated block index and avoids the manual chain-ordering step.

use std::{
    collections::HashMap,
    fs,
    io::{self, BufReader, Read, Seek, SeekFrom},
    ops::ControlFlow,
    path::{Path, PathBuf},
};

use bitcoin::{BlockHash, block::Header, consensus::deserialize, hashes::Hash};

use crate::chain::{
    error::ChainError,
    stream::{BlockSource, RawBlock},
};

/// Reads blocks from Bitcoin Core's raw `blk*.dat` files.
///
/// Handles XOR obfuscation (Bitcoin Core v28+) and chains blocks by
/// `prev_blockhash` to produce canonical height ordering. For mainnet
/// production use, prefer [`KernelBlockReader`](super::kernel_reader::KernelBlockReader)
/// which uses the validated block index.
pub struct BlkFileReader {
    blocks_dir: PathBuf,
    xor_key: Vec<u8>,
}

impl BlkFileReader {
    /// Opens a blocks directory for reading.
    ///
    /// Reads the XOR key from `xor.dat` if present.
    ///
    /// # Errors
    ///
    /// Returns [`io::Error`] if `blocks_dir` cannot be read or `xor.dat`
    /// exists but is unreadable.
    pub fn open(blocks_dir: &Path) -> io::Result<Self> {
        let xor_path = blocks_dir.join("xor.dat");
        let xor_key = if xor_path.exists() {
            fs::read(&xor_path)?
        } else {
            vec![]
        };

        Ok(Self {
            blocks_dir: blocks_dir.to_path_buf(),
            xor_key,
        })
    }

    /// List all blk*.dat files in sorted order.
    fn blk_files(&self) -> io::Result<Vec<PathBuf>> {
        let mut files: Vec<PathBuf> = fs::read_dir(&self.blocks_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("blk") && n.ends_with(".dat"))
                    .unwrap_or(false)
            })
            .collect();
        files.sort();
        Ok(files)
    }

    /// De-obfuscate a buffer in place, starting at the given file offset.
    fn deobfuscate_in_place(&self, file_offset: u64, buf: &mut [u8]) {
        if self.xor_key.is_empty() {
            return;
        }
        let key_len = self.xor_key.len();
        for byte in buf.iter_mut() {
            *byte ^= self.xor_key[(file_offset as usize + 1) % key_len];
        }
    }

    /// Scan a single blk file, `emit` for each block found.
    fn scan_blk_file(
        &self,
        path: &Path,
        emit: &mut dyn FnMut(BlockHash, Vec<u8>) -> Result<ControlFlow<()>, ChainError>,
    ) -> Result<(), ChainError> {
        let file = fs::File::open(path)?;

        let file_len = file.metadata()?.len();
        if file_len < 8 {
            return Ok(());
        }

        let mut reader = BufReader::with_capacity(1 << 20, file);

        let mut magic_buf = [0u8; 4];
        reader.read_exact(&mut magic_buf)?;
        self.deobfuscate_in_place(0, &mut magic_buf);
        let expected_magic = magic_buf;

        reader.seek(SeekFrom::Start(0))?;
        let mut file_offset = 0;
        let mut header_buf = [0u8; 8];

        while file_offset + 8 <= file_len {
            if reader.read_exact(&mut header_buf).is_err() {
                break;
            }
            self.deobfuscate_in_place(file_offset, &mut header_buf);

            let magic = &header_buf[0..4];
            if magic == [0, 0, 0, 0] {
                break;
            }

            if magic != expected_magic {
                file_offset += 1;
                reader.seek(SeekFrom::Start(file_offset))?;
                continue;
            }

            let size = u32::from_le_bytes(header_buf[4..8].try_into().unwrap()) as usize;
            if size == 0 || size > 4_000_000 {
                break;
            }

            let data_offset = file_offset + 8;
            if data_offset + size as u64 > file_len {
                break;
            }

            let mut block_data = vec![0u8; size];
            if reader.read_exact(&mut block_data).is_err() {
                break;
            }
            self.deobfuscate_in_place(data_offset, &mut block_data);

            file_offset = data_offset + size as u64;

            if block_data.len() >= 80 {
                match deserialize::<Header>(&block_data[..80]) {
                    Ok(header) => {
                        let hash = header.block_hash();
                        if let ControlFlow::Break(()) = emit(hash, block_data)? {
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Warning: failed to parse block header at offset {}: {}",
                            data_offset, e
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

struct BlockMeta {
    hash: BlockHash,
    prev_hash: BlockHash,
    data: Vec<u8>,
}

/// Two-pass strategy: first scans every `blk*.dat` file to collect all blocks
/// into memory, then walks the `prev_blockhash` chain from genesis to produce
/// height-ordered [`RawBlock`]s.
impl BlockSource for BlkFileReader {
    fn for_each_block(
        &self,
        visitor: &mut dyn FnMut(super::stream::RawBlock) -> Result<ControlFlow<()>, ChainError>,
    ) -> Result<(), ChainError> {
        let blk_files = self.blk_files()?;
        let mut blocks_by_hash: HashMap<BlockHash, BlockMeta> = HashMap::new();
        let mut genesis_hash: Option<BlockHash> = None;

        for blk_path in &blk_files {
            self.scan_blk_file(blk_path, &mut |hash, data| {
                let header: Header =
                    deserialize(&data[..80]).map_err(|e| ChainError::Parse(e.to_string()))?;
                let prev = header.prev_blockhash;
                if prev == BlockHash::all_zeros() {
                    genesis_hash = Some(hash);
                }
                blocks_by_hash.insert(
                    hash,
                    BlockMeta {
                        hash,
                        prev_hash: prev,
                        data,
                    },
                );
                Ok(ControlFlow::Continue(()))
            })?;
        }

        let mut child_of: HashMap<BlockHash, BlockHash> = HashMap::new();
        for meta in blocks_by_hash.values() {
            child_of.insert(meta.prev_hash, meta.hash);
        }

        let gen_hash =
            genesis_hash.ok_or_else(|| ChainError::Parse("no genesis block found".into()))?;
        let mut current = gen_hash;
        let mut height = 0;

        while let Some(m) = blocks_by_hash.remove(&current) {
            let block = RawBlock {
                height,
                hash: m.hash.to_string(),
                data: m.data,
            };

            if let ControlFlow::Break(()) = visitor(block)? {
                return Ok(());
            }

            height += 1;
            match child_of.get(&current) {
                Some(&next) => current = next,
                None => break,
            }
        }
        Ok(())
    }
}
