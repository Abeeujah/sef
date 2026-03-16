//! Superblock grouping for SeF-secure fountain encoding.
//!
//! A *superblock* concatenates consecutive whole Bitcoin blocks into a single
//! LT source unit, preserving block boundaries so that recovered singletons
//! can be verified against the independently obtained header chain.
//!
//! Unlike [`symbol`](crate::symbol) mode (which slices at arbitrary
//! [`DEFAULT_SYMBOL_SIZE`](crate::symbol::DEFAULT_SYMBOL_SIZE)-byte
//! boundaries), superblocks guarantee that **every source unit is
//! independently verifiable** from trusted block hashes — the core security
//! property required by the SeF paper (§3.2.3, §5.1).
//!
//! ## Grouping strategy
//!
//! Per SeF §5.1, blocks are concatenated greedily until adding the next block
//! would exceed a **target byte size** $L_s$.  This keeps superblocks
//! approximately equal in size, minimizing XOR padding waste during fountain
//! encoding.
//!
//! # Examples
//!
//! ```
//! use sef::superblock::blocks_to_superblocks;
//!
//! let blocks = vec![vec![0xAAu8; 400], vec![0xBBu8; 300], vec![0xCCu8; 500]];
//! let (supers, ranges) = blocks_to_superblocks(&blocks, 800);
//!
//! assert_eq!(supers.len(), 2);           // blocks 0+1 fit in 800; block 2 starts a new one
//! assert_eq!(supers[0].len(), 700);      // 400 + 300
//! assert_eq!(ranges[0], 0..2);
//! assert_eq!(ranges[1], 2..3);
//! ```

use std::ops::Range;

use bitcoin::{
    VarInt,
    consensus::{Decodable, Encodable, deserialize_partial, encode},
    io::Cursor,
};

/// Metadata sidecar persisted alongside superblock-encoded droplets.
///
/// Records the information needed by the standalone decoder to reconstruct
/// individual blocks from decoded superblocks without access to the original
/// chain. Analogous to [`SymbolManifest`](crate::symbol::SymbolManifest) for
/// symbol-mode encoding.
///
/// ## Wire format
///
/// ```text
/// VarInt(total_blocks)
/// VarInt(total_supers)
/// VarInt(counts[0]) || VarInt(counts[1]) || ... || VarInt(counts[total_supers - 1])
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SuperblockManifest {
    /// Total number of original blocks in the epoch.
    pub total_blocks: usize,

    /// Total number of superblocks produced by [`blocks_to_superblocks`].
    pub total_supers: usize,

    /// Number of blocks in each superblock. Ranges are reconstructed via
    /// prefix sums in [`ranges_from_manifest`].
    pub block_counts: Vec<usize>,
}

impl Encodable for SuperblockManifest {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += VarInt(self.total_blocks as u64).consensus_encode(writer)?;
        len += VarInt(self.total_supers as u64).consensus_encode(writer)?;
        for &count in &self.block_counts {
            len += VarInt(count as u64).consensus_encode(writer)?;
        }
        Ok(len)
    }
}

impl Decodable for SuperblockManifest {
    fn consensus_decode_from_finite_reader<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let total_blocks = VarInt::consensus_decode_from_finite_reader(reader)?.0 as usize;
        let total_supers = VarInt::consensus_decode_from_finite_reader(reader)?.0 as usize;

        let mut block_counts = Vec::with_capacity(total_supers);
        for _ in 0..total_supers {
            block_counts.push(VarInt::consensus_decode_from_finite_reader(reader)?.0 as usize);
        }

        Ok(SuperblockManifest {
            total_blocks,
            total_supers,
            block_counts,
        })
    }
}

/// Serializes a [`SuperblockManifest`] to bytes using Bitcoin consensus encoding.
pub fn serialize_manifest(manifest: &SuperblockManifest) -> Vec<u8> {
    encode::serialize(manifest)
}

/// Deserializes a [`SuperblockManifest`] from bytes produced by [`serialize_manifest`].
pub fn deserialize_manifest(data: &[u8]) -> Result<SuperblockManifest, encode::Error> {
    encode::deserialize(data)
}

/// Serializes a slice of trusted block headers to raw bytes.
///
/// Each header is exactly 80 bytes in Bitcoin's consensus encoding.
/// The resulting blob is simply the concatenation of all headers,
/// suitable for flat-file storage.
pub fn serialize_headers(headers: &[bitcoin::block::Header]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(headers.len() * 80);
    for h in headers {
        h.consensus_encode(&mut buf)
            .expect("header encode infallible");
    }
    buf
}

/// Deserializes trusted block headers from a flat byte buffer produced
/// by [`serialize_headers`].
pub fn deserialize_headers(data: &[u8]) -> Result<Vec<bitcoin::block::Header>, encode::Error> {
    let mut headers = Vec::with_capacity(data.len() / 80);
    let mut cursor = Cursor::new(data);
    while (cursor.position() as usize) < data.len() {
        headers.push(bitcoin::block::Header::consensus_decode_from_finite_reader(
            &mut cursor,
        )?);
    }
    Ok(headers)
}

/// Reconstructs the block-index ranges from a [`SuperblockManifest`].
///
/// Ranges are derived via prefix sums over [`SuperblockManifest::block_counts`].
pub fn ranges_from_manifest(manifest: &SuperblockManifest) -> Vec<Range<usize>> {
    let mut start = 0;
    manifest
        .block_counts
        .iter()
        .map(|&count| {
            let end = start + count;
            let range = start..end;
            start = end;
            range
        })
        .collect()
}

/// Groups consecutive blocks into superblocks using a **target byte size**,
/// following the SeF paper §5.1.
///
/// Blocks are greedily concatenated into the current superblock. Whenadding
/// the next block would exceed `target_bytes`, the current superblock is
/// finalized and a new one is started. A single block that exceeds
/// `target_bytes` on its own becomes a singleton superblock.
///
/// Returns `(superblocks, ranges)` where:
/// - `superblocks[i]` is the concatenated bytes of `blocks[ranges[i]]`
/// - `ranges[i]` maps each superblock index to its block-index range
///
/// # Panics
///
/// Panics if `target_bytes == 0`.
pub fn blocks_to_superblocks(
    blocks: &[Vec<u8>],
    target_bytes: usize,
) -> (Vec<Vec<u8>>, Vec<Range<usize>>) {
    assert!(target_bytes > 0, "target_bytes must be > 0");

    let total_bytes: usize = blocks.iter().map(|b| b.len()).sum();
    let capacity = total_bytes.div_ceil(target_bytes).max(1);

    let mut supers: Vec<Vec<u8>> = Vec::with_capacity(capacity);
    let mut ranges: Vec<Range<usize>> = Vec::with_capacity(capacity);

    let mut start = 0;
    let mut cur = Vec::with_capacity(target_bytes);

    for (i, block) in blocks.iter().enumerate() {
        if !cur.is_empty() && cur.len() + block.len() > target_bytes {
            supers.push(std::mem::take(&mut cur));
            ranges.push(start..i);
            start = i;
            cur = Vec::with_capacity(target_bytes);
        }
        cur.extend_from_slice(block);
    }

    if !cur.is_empty() {
        supers.push(cur);
        ranges.push(start..blocks.len());
    }
    (supers, ranges)
}

/// Reassembles individual blocks from decoded superblocks.
///
/// For each superblock that is `Some`, uses
/// [`bitcoin::consensus::deserialize_partial`] to sequentially parse the
/// expected number of blocks (from `ranges`). Returns `None` for blocks
/// whose superblock was not recovered.
///
/// This is the inverse of [`blocks_to_superblocks`] for the decode path,
/// relying on Bitcoin's self-delimiting consensus encoding to locate block
/// boundaries within each concatenated superblock.
pub fn superblocks_to_blocks(
    superblocks: &[Option<Vec<u8>>],
    ranges: &[Range<usize>],
    total_blocks: usize,
) -> Vec<Option<Vec<u8>>> {
    let mut result: Vec<Option<Vec<u8>>> = vec![None; total_blocks];

    for (si, range) in ranges.iter().enumerate() {
        let superblock = match superblocks.get(si).and_then(|s| s.as_ref()) {
            Some(sb) => sb,
            None => continue,
        };

        let mut offset = 0;
        for block_idx in range.clone() {
            if offset >= superblock.len() {
                break;
            }
            match deserialize_partial::<bitcoin::Block>(&superblock[offset..]) {
                Ok((_block, consumed)) => {
                    result[block_idx] = Some(superblock[offset..offset + consumed].to_vec());
                    offset += consumed;
                }
                Err(_) => break,
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Produces `sizes.len()` blocks with deterministic fill patterns.
    fn make_fake_blocks(sizes: &[usize]) -> Vec<Vec<u8>> {
        sizes
            .iter()
            .enumerate()
            .map(|(i, &sz)| vec![(i as u8).wrapping_mul(31); sz])
            .collect()
    }

    #[test]
    fn grouping_by_target_size() {
        // 100 + 200 = 300 ≤ 350, but 300 + 300 = 600 > 350
        let blocks = make_fake_blocks(&[100, 200, 300, 400]);
        let (supers, ranges) = blocks_to_superblocks(&blocks, 350);

        assert_eq!(supers.len(), 3);
        assert_eq!(ranges, [0..2, 2..3, 3..4]);
        assert_eq!(supers[0].len(), 300); // 100 + 200
        assert_eq!(supers[1].len(), 300);
        assert_eq!(supers[2].len(), 400);
    }

    #[test]
    fn all_fit_in_one() {
        let blocks = make_fake_blocks(&[100, 200, 300]);
        let (supers, ranges) = blocks_to_superblocks(&blocks, 10_000);

        assert_eq!(supers.len(), 1);
        assert_eq!(ranges[0], 0..3);
        assert_eq!(supers[0].len(), 600);
    }

    #[test]
    fn oversized_block_becomes_singleton() {
        let blocks = make_fake_blocks(&[100, 5000, 200]);
        let (supers, ranges) = blocks_to_superblocks(&blocks, 1000);

        assert_eq!(supers.len(), 3);
        assert_eq!(ranges[1], 1..2);
        assert_eq!(supers[1].len(), 5000);
    }

    #[test]
    fn each_block_own_superblock_when_target_tiny() {
        let blocks = make_fake_blocks(&[100, 200]);
        let (supers, ranges) = blocks_to_superblocks(&blocks, 1);

        assert_eq!(supers.len(), 2);
        assert_eq!(ranges, [0..1, 1..2]);
        assert_eq!(supers[0], blocks[0]);
        assert_eq!(supers[1], blocks[1]);
    }

    #[test]
    fn empty_input_produces_empty_output() {
        let (supers, ranges) = blocks_to_superblocks(&[], 5000);

        assert!(supers.is_empty());
        assert!(ranges.is_empty());
    }

    #[test]
    #[should_panic(expected = "target_bytes must be > 0")]
    fn zero_target_panics() {
        blocks_to_superblocks(&make_fake_blocks(&[100]), 0);
    }

    #[test]
    fn manifest_serialization_roundtrip() {
        let manifest = SuperblockManifest {
            total_blocks: 95,
            total_supers: 3,
            block_counts: vec![40, 30, 25],
        };
        let bytes = serialize_manifest(&manifest);
        let recovered = deserialize_manifest(&bytes).unwrap();
        assert_eq!(manifest, recovered);
    }

    #[test]
    fn ranges_from_manifest_matches_grouping() {
        let blocks = make_fake_blocks(&[100, 200, 300, 400, 500]);
        let (_supers, ranges) = blocks_to_superblocks(&blocks, 350);

        let counts: Vec<usize> = ranges.iter().map(|r| r.end - r.start).collect();
        let manifest = SuperblockManifest {
            total_blocks: 5,
            total_supers: counts.len(),
            block_counts: counts,
        };
        assert_eq!(ranges_from_manifest(&manifest), ranges);
    }
}
