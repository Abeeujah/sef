use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
};

use bitcoin::{Block, BlockHash, consensus::deserialize, hashes::Hash};

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

/// Read all blocks from Bitcoin Core's `blk*.dat` files in a data directory.
///
/// Handles the XOR obfuscation introduced in Bitcoin Core v28 (reads `xor.dat`).
/// Returns the blocks in file order - for signet with a single blk file and no forks,
/// this is the canonical chain order.
pub struct BlkFileReader {
    blocks_dir: PathBuf,
    xor_key: Vec<u8>,
}

impl BlkFileReader {
    /// Open a blocks directory for reading.
    ///
    /// Reads the XOR key from `xor.dat` if present
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

    /// De-obfuscate data using the XOR key.
    fn deobfuscate(&self, data: &[u8]) -> Vec<u8> {
        if self.xor_key.is_empty() {
            return data.to_vec();
        }
        let key_len = self.xor_key.len();
        data.iter()
            .enumerate()
            .map(|(i, &b)| b ^ self.xor_key[i % key_len])
            .collect()
    }

    /// Read all blocks from all blk*.dat files.
    ///
    /// Parses the raw file format: `[4B magic][4B size][size bytes block_data]` repeated.
    /// Returns blocks in chain order (file order). Each block is verified by parsing
    /// with the `bitcoin` crate's consensus deserializer.
    pub fn read_all_blocks(&self) -> io::Result<Vec<RawBlock>> {
        let mut all_blocks = Vec::new();
        let blk_files = self.blk_files()?;

        for blk_path in &blk_files {
            let raw_data = fs::read(blk_path)?;
            let data = self.deobfuscate(&raw_data);
            let blocks = self.parse_blk_data(&data)?;
            all_blocks.extend(blocks);
        }

        // Chain blocks by following prev_blockhash from genesis.
        // This ensures correct ordering even if file order differs.
        let ordered = order_blocks_by_chain(all_blocks)?;
        Ok(ordered)
    }

    /// Parse blocks from a de-obfuscated blk file buffer.
    fn parse_blk_data(&self, data: &[u8]) -> io::Result<Vec<(String, Vec<u8>)>> {
        let mut blocks = Vec::new();
        let mut offset = 0;

        // Read the magic from the first block to identify the network
        if data.len() < 8 {
            return Ok(blocks);
        }
        let expected_magic = &data[0..4];

        while offset + 8 <= data.len() {
            let magic = &data[offset..offset + 4];

            // Check for zero-padding (end of data)
            if magic == [0, 0, 0, 0] {
                break;
            }

            // Verify magic matches
            if magic != expected_magic {
                // Might be padding or corruption; try to skip
                offset += 1;
                continue;
            }

            let size =
                u32::from_le_bytes(data[offset + 4..offset + 8].try_into().unwrap()) as usize;

            if size == 0 || size > 4_000_000 {
                break;
            }

            if offset + 8 + size > data.len() {
                break;
            }

            let block_data = &data[offset + 8..offset + 8 + size];

            // Parse with bitcoin crate to get the block hash
            match deserialize::<Block>(block_data) {
                Ok(block) => {
                    let hash = block.block_hash().to_string();
                    blocks.push((hash, block_data.to_vec()));
                }
                Err(e) => {
                    eprintln!("Warning: failed to parse block at offset {}: {}", offset, e)
                }
            }
            offset += 8 + size;
        }
        Ok(blocks)
    }
}

/// Order blocks by following the prev_blockhash chain from genesis.
fn order_blocks_by_chain(unordered: Vec<(String, Vec<u8>)>) -> io::Result<Vec<RawBlock>> {
    if unordered.is_empty() {
        return Ok(vec![]);
    }

    // Build a map: prev_hash -> [(hash, data)]
    let mut by_prev: HashMap<String, Vec<(String, Vec<u8>)>> = HashMap::new();
    let mut genesis: Option<(String, Vec<u8>)> = None;

    for (hash, data) in unordered {
        let block: Block = deserialize(&data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        let prev = block.header.prev_blockhash.to_string();

        // Genesis block has prev_blockhash = 0...0
        let is_genesis = block.header.prev_blockhash == BlockHash::all_zeros();
        if is_genesis {
            genesis = Some((hash, data));
        } else {
            by_prev.entry(prev).or_default().push((hash, data));
        }
    }

    let mut ordered = Vec::new();
    let (gen_hash, gen_data) = genesis
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no genesis block found"))?;

    ordered.push(RawBlock {
        height: 0,
        hash: gen_hash.clone(),
        data: gen_data,
    });

    let mut current_hash = gen_hash;
    let mut height = 1u32;

    loop {
        match by_prev.get_mut(&current_hash) {
            Some(children) if !children.is_empty() => {
                let (hash, data) = children.remove(0);
                ordered.push(RawBlock {
                    height,
                    hash: hash.clone(),
                    data,
                });
                current_hash = hash;
                height += 1;
            }
            _ => break,
        }
    }
    Ok(ordered)
}

/// Group blocks into epochs of size `k`.
///
/// The last epoch may be smaller than `k` (a "tail epoch").
/// The most recent `buffer` blocks are excluded from encoding.
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
}
