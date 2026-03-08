//! Normalizes variable-length blockchain data into uniform fixed-size symbols for fountain encoding.
//!
//! Without normalization, the RSD-based encoder must pad every XOR operation to
//! the length of the largest block in the epoch, wasting bandwidth proportional
//! to the variance in block sizes. This module concatenates all blocks into a
//! single contiguous byte stream, then slices that stream into fixed-size chunks
//! of [`DEFAULT_SYMBOL_SIZE`] bytes. Only the final symbol may contain
//! zero-padding.
//!
//! Concatenation reduces the effective $K$ for the fountain code—many small
//! blocks pack into fewer symbols—improving both RSD efficiency and decoding
//! probability. The [`SymbolManifest`] tracks the mapping from symbols back to
//! original blocks, enabling reassembly after decoding.
//!
//! **Dependency graph position:** downstream of raw block ingestion
//! (`crate::chain`), upstream of [`crate::droplet::Encoder`].
//!
//! # Examples
//!
//! ```
//! use sef::symbol::{blocks_to_symbols, symbols_to_blocks, DEFAULT_SYMBOL_SIZE};
//!
//! let blocks = vec![vec![0xAAu8; 300], vec![0xBBu8; 500]];
//! let (symbols, manifest) = blocks_to_symbols(&blocks, DEFAULT_SYMBOL_SIZE);
//!
//! // Simulate a full decode: all symbols recovered.
//! let decoded: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
//! let recovered = symbols_to_blocks(&decoded, &manifest);
//!
//! assert_eq!(recovered[0].as_ref().unwrap(), &blocks[0]);
//! assert_eq!(recovered[1].as_ref().unwrap(), &blocks[1]);
//! ```

use bitcoin::{
    VarInt,
    consensus::{Decodable, Encodable, encode},
};
use sha2::{Digest, Sha256};

/// Default symbol size in bytes (4 KiB).
///
/// Aligns with typical filesystem page size and provides a reasonable
/// trade-off between symbol count (lower $K$ → better RSD efficiency)
/// and padding overhead on the final symbol.
pub const DEFAULT_SYMBOL_SIZE: usize = 4096;

/// Metadata sidecar that maps decoded symbols back to original blocks.
///
/// After the fountain decoder recovers individual symbols, this manifest
/// provides the byte-level mapping needed to reassemble the original
/// variable-length blocks from the concatenated symbol stream. It must be
/// distributed alongside the encoded droplets (or stored out-of-band) so
/// that any decoder can reconstruct the original data.
///
/// Implements [`Encodable`] / [`Decodable`] for consensus-compatible
/// serialization, making it suitable for on-chain or P2P transport.
#[derive(Debug, Clone, PartialEq)]
pub struct SymbolManifest {
    /// Symbol size in bytes. Every symbol—including the final one—is
    /// exactly this length (the tail is zero-padded).
    pub symbol_size: usize,

    /// Total number of symbols produced by [`blocks_to_symbols`].
    pub total_symbols: usize,

    /// Per-block metadata recording each block's position and true length
    /// within the concatenated byte stream. See [`BlockEntry`].
    pub block_entries: Vec<BlockEntry>,

    /// SHA-256 hash of each symbol, used for integrity verification during
    /// peeling decode.
    pub symbol_hashes: Vec<[u8; 32]>,
}

/// Manifest entry describing a single original block's position in the concatenated stream.
///
/// Used by [`symbols_to_blocks`] to extract the correct byte range from the
/// reassembled symbol stream.
#[derive(Debug, Clone, PartialEq)]
pub struct BlockEntry {
    /// Byte offset of this block relative to the *concatenated* byte stream
    /// (not relative to any individual block or symbol boundary).
    pub byte_offset: usize,

    /// True serialized byte length of the block before zero-padding.
    pub true_len: usize,
}

/// Concatenates `blocks` into a single byte stream, then slices into fixed-size symbols.
///
/// Unlike a per-block splitting strategy (where each block is independently
/// padded to `symbol_size`), concatenation packs data tightly: block
/// boundaries may fall mid-symbol, and only the final symbol carries
/// zero-padding. This reduces the total symbol count—and therefore the
/// effective $K$—yielding better RSD efficiency and decoding probability.
///
/// Returns `(symbols, manifest)` where every symbol is exactly `symbol_size`
/// bytes and [`SymbolManifest`] records the mapping back to original blocks.
///
/// # Panics
///
/// Panics if `symbol_size == 0`.
pub fn blocks_to_symbols(blocks: &[Vec<u8>], symbol_size: usize) -> (Vec<Vec<u8>>, SymbolManifest) {
    assert!(symbol_size > 0, "symbol_size must be positive");

    // Record each block's byte offset and length in the concatenated stream
    let mut block_entries = Vec::with_capacity(blocks.len());
    let mut byte_offset = 0;
    for block in blocks {
        block_entries.push(BlockEntry {
            byte_offset,
            true_len: block.len(),
        });
        byte_offset += block.len();
    }

    let total_bytes = byte_offset;
    let total_symbols = if total_bytes == 0 {
        0
    } else {
        total_bytes.div_ceil(symbol_size)
    };

    // Stream blocks directly into fixed-size symbol buffers (no intermediate concat)
    let mut symbols: Vec<Vec<u8>> = Vec::with_capacity(total_symbols);
    let mut sym_buf = vec![0u8; symbol_size];
    let mut sym_pos = 0;

    for block in blocks {
        let mut remaining = block.as_slice();
        while !remaining.is_empty() {
            let space = symbol_size - sym_pos;
            let n = remaining.len().min(space);
            sym_buf[sym_pos..sym_pos + n].copy_from_slice(&remaining[..n]);
            sym_pos += n;
            remaining = &remaining[n..];
            if sym_pos == symbol_size {
                symbols.push(std::mem::replace(&mut sym_buf, vec![0u8; symbol_size]));
                sym_pos = 0;
            }
        }
    }

    // Flush the last partial symbol (already zero-padded by initial vec![0u8; ..])
    if sym_pos > 0 {
        symbols.push(sym_buf);
    }

    let symbol_hashes: Vec<[u8; 32]> = symbols
        .iter()
        .map(|sym| Sha256::new().chain_update(sym).finalize().into())
        .collect();

    let manifest = SymbolManifest {
        symbol_size,
        total_symbols: symbols.len(),
        block_entries,
        symbol_hashes,
    };

    (symbols, manifest)
}

/// Reconstructs original blocks from decoded symbols using the [`SymbolManifest`].
///
/// For each [`BlockEntry`] in the manifest, the function identifies the
/// symbol range that covers `[byte_offset, byte_offset + true_len)` in the
/// concatenated stream. If every symbol in that range is `Some`, the block
/// bytes are extracted and returned. Otherwise, the entry yields `None`,
/// enabling partial-recovery semantics: callers can determine exactly which
/// original blocks were successfully decoded.
pub fn symbols_to_blocks(
    symbols: &[Option<Vec<u8>>],
    manifest: &SymbolManifest,
) -> Vec<Option<Vec<u8>>> {
    let sym_size = manifest.symbol_size;

    manifest
        .block_entries
        .iter()
        .map(|entry| {
            let byte_offset = entry.byte_offset;
            let true_len = entry.true_len;

            if true_len == 0 {
                return Some(Vec::new());
            }

            let first_sym = byte_offset / sym_size;
            let last_sym = (byte_offset + true_len - 1) / sym_size;

            for si in first_sym..=last_sym {
                symbols.get(si).and_then(|s| s.as_ref())?;
            }

            let mut block = Vec::with_capacity(true_len);
            let mut remaining = true_len;
            let mut stream_pos = byte_offset;

            while remaining > 0 {
                let si = stream_pos / sym_size;
                let offset_in_sym = stream_pos % sym_size;
                let available = sym_size - offset_in_sym;
                let to_copy = remaining.min(available);

                let sym = symbols[si].as_ref().unwrap();
                block.extend_from_slice(&sym[offset_in_sym..offset_in_sym + to_copy]);

                stream_pos += to_copy;
                remaining -= to_copy;
            }

            Some(block)
        })
        .collect()
}

/// Wire format: `VarInt(byte_offset) || VarInt(true_len)`.
impl Encodable for BlockEntry {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += VarInt(self.byte_offset as u64).consensus_encode(writer)?;
        len += VarInt(self.true_len as u64).consensus_encode(writer)?;
        Ok(len)
    }
}

/// Decodes `VarInt(byte_offset) || VarInt(true_len)`.
impl Decodable for BlockEntry {
    fn consensus_decode_from_finite_reader<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let byte_offset = VarInt::consensus_decode_from_finite_reader(reader)?.0 as usize;
        let true_len = VarInt::consensus_decode_from_finite_reader(reader)?.0 as usize;
        Ok(BlockEntry {
            byte_offset,
            true_len,
        })
    }
}

/// Wire format: `VarInt(symbol_size) || VarInt(total_symbols) || VarInt(n_entries) || [BlockEntry; n_entries] || VarInt(n_hashes) || [[u8; 32]; n_hashes]`.
impl Encodable for SymbolManifest {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += VarInt(self.symbol_size as u64).consensus_encode(writer)?;
        len += VarInt(self.total_symbols as u64).consensus_encode(writer)?;
        len += VarInt(self.block_entries.len() as u64).consensus_encode(writer)?;
        for entry in &self.block_entries {
            len += entry.consensus_encode(writer)?;
        }
        len += VarInt(self.symbol_hashes.len() as u64).consensus_encode(writer)?;
        for hash in &self.symbol_hashes {
            writer.write_all(hash)?;
            len += 32;
        }
        Ok(len)
    }
}

/// Inverse of the [`SymbolManifest`] [`Encodable`] impl.
impl Decodable for SymbolManifest {
    fn consensus_decode_from_finite_reader<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let symbol_size = VarInt::consensus_decode_from_finite_reader(reader)?.0 as usize;
        let total_symbols = VarInt::consensus_decode_from_finite_reader(reader)?.0 as usize;
        let num_entries = VarInt::consensus_decode_from_finite_reader(reader)?.0 as usize;
        let mut block_entries = Vec::with_capacity(num_entries);
        for _ in 0..num_entries {
            block_entries.push(BlockEntry::consensus_decode_from_finite_reader(reader)?);
        }
        let num_hashes = VarInt::consensus_decode_from_finite_reader(reader)?.0 as usize;
        let mut symbol_hashes = Vec::with_capacity(num_hashes);
        for _ in 0..num_hashes {
            let mut hash = [0u8; 32];
            reader.read_exact(&mut hash)?;
            symbol_hashes.push(hash);
        }
        Ok(SymbolManifest {
            symbol_size,
            total_symbols,
            block_entries,
            symbol_hashes,
        })
    }
}

/// Serializes a [`SymbolManifest`] to bytes using Bitcoin consensus encoding.
pub fn serialize_manifest(manifest: &SymbolManifest) -> Vec<u8> {
    encode::serialize(manifest)
}

/// Deserializes a [`SymbolManifest`] from bytes produced by [`serialize_manifest`].
pub fn deserialize_manifest(data: &[u8]) -> Result<SymbolManifest, encode::Error> {
    encode::deserialize(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::slice::from_ref;

    #[test]
    fn test_roundtrip_identical_blocks() {
        let blocks: Vec<Vec<u8>> = (0..5).map(|i| vec![(i as u8) * 11; 1000]).collect();

        let (symbols, manifest) = blocks_to_symbols(&blocks, 256);

        // All symbols are present
        let all_symbols: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        let recovered = symbols_to_blocks(&all_symbols, &manifest);

        for (i, block) in recovered.iter().enumerate() {
            assert_eq!(block.as_ref().unwrap(), &blocks[i], "block {} mismatch", i);
        }
    }

    #[test]
    fn test_roundtrip_different_sizes() {
        let blocks = vec![
            vec![0xAA; 300],
            vec![0xBB; 170_000],
            vec![0xCC; 1],
            vec![0xDD; 4096],
            vec![0xEE; 8193],
        ];

        let (symbols, manifest) = blocks_to_symbols(&blocks, 4096);

        let all_symbols: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        let recovered = symbols_to_blocks(&all_symbols, &manifest);

        for (i, block) in recovered.iter().enumerate() {
            assert_eq!(
                block.as_ref().unwrap(),
                &blocks[i],
                "block {} roundtrip failed (len {} vs {})",
                i,
                block.as_ref().unwrap().len(),
                blocks[i].len()
            );
        }
    }

    #[test]
    fn test_concatenation_reduces_symbols() {
        // 4 blocks of 300 bytes each = 1200 bytes total
        // With concatenation: ceil(1200/4096) = 1 symbol (not 4!)
        let blocks: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8; 300]).collect();
        let (symbols, manifest) = blocks_to_symbols(&blocks, 4096);

        assert_eq!(symbols.len(), 1); // All 4 blocks fit in 1 symbol
        assert_eq!(manifest.total_symbols, 1);
        assert_eq!(symbols[0].len(), 4096);
    }

    #[test]
    fn test_all_symbols_fixed_size() {
        let blocks = vec![vec![0xAA; 100], vec![0xBB; 5000], vec![0xCC; 8192]];
        let (symbols, _manifest) = blocks_to_symbols(&blocks, 4096);

        for (i, sym) in symbols.iter().enumerate() {
            assert_eq!(sym.len(), 4096, "symbol {} has wrong size {}", i, sym.len());
        }
    }

    #[test]
    fn test_zero_padding_only_last_symbol() {
        // 100 bytes → 1 symbol, last 3996 bytes are zeros
        let block = vec![0xFF; 100];
        let (symbols, _manifest) = blocks_to_symbols(from_ref(&block), 4096);

        assert_eq!(symbols.len(), 1);
        assert_eq!(&symbols[0][..100], &[0xFF; 100]);
        assert_eq!(&symbols[0][100..], &vec![0u8; 3996]);
    }

    #[test]
    fn test_multi_symbol_single_block() {
        // 5000 bytes → ceil(5000/4096) = 2 symbols
        let block: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();
        let (symbols, _manifest) = blocks_to_symbols(from_ref(&block), 4096);

        assert_eq!(symbols.len(), 2);
        assert_eq!(&symbols[0], &block[..4096]);
        assert_eq!(&symbols[1][..904], &block[4096..]);
        assert_eq!(&symbols[1][904..], &vec![0u8; 4096 - 904]);
    }

    #[test]
    fn test_manifest_byte_offsets() {
        let blocks = vec![vec![0u8; 100], vec![0u8; 200], vec![0u8; 300]];
        let (_symbols, manifest) = blocks_to_symbols(&blocks, 4096);

        assert_eq!(manifest.block_entries[0].byte_offset, 0);
        assert_eq!(manifest.block_entries[0].true_len, 100);
        assert_eq!(manifest.block_entries[1].byte_offset, 100);
        assert_eq!(manifest.block_entries[1].true_len, 200);
        assert_eq!(manifest.block_entries[2].byte_offset, 300);
        assert_eq!(manifest.block_entries[2].true_len, 300);
        // Total: 600 bytes → 1 symbol
        assert_eq!(manifest.total_symbols, 1);
    }

    #[test]
    fn test_missing_symbol_returns_none() {
        // 2 blocks spanning 2 symbols: block0 in sym0, block1 spans sym0+sym1
        let blocks = vec![vec![0xAA; 3000], vec![0xBB; 3000]];
        let (symbols, manifest) = blocks_to_symbols(&blocks, 4096);
        // 6000 bytes → 2 symbols

        assert_eq!(symbols.len(), 2);

        // Remove second symbol
        let mut partial: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        partial[1] = None;

        let recovered = symbols_to_blocks(&partial, &manifest);
        // Block 0 fits entirely in sym 0 → recoverable
        assert!(recovered[0].is_some());
        // Block 1 spans sym 0 and sym 1 → not recoverable
        assert!(recovered[1].is_none());
    }

    #[test]
    fn test_empty_block() {
        let blocks = vec![vec![], vec![0xAA; 100]];
        let (symbols, manifest) = blocks_to_symbols(&blocks, 4096);

        assert_eq!(manifest.block_entries[0].true_len, 0);
        // Only 100 bytes total → 1 symbol
        assert_eq!(symbols.len(), 1);

        let all_symbols: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        let recovered = symbols_to_blocks(&all_symbols, &manifest);
        assert_eq!(recovered[0].as_ref().unwrap(), &Vec::<u8>::new());
        assert_eq!(recovered[1].as_ref().unwrap(), &vec![0xAA; 100]);
    }

    #[test]
    fn test_manifest_serialization_roundtrip() {
        let blocks = vec![vec![0u8; 300], vec![0u8; 170_000], vec![0u8; 4096]];
        let (_symbols, manifest) = blocks_to_symbols(&blocks, 4096);
        let bytes = serialize_manifest(&manifest);
        let recovered = deserialize_manifest(&bytes).unwrap();
        assert_eq!(manifest, recovered);
    }

    #[test]
    fn test_small_symbol_size() {
        let block = vec![0xAB; 10];
        let (symbols, _manifest) = blocks_to_symbols(from_ref(&block), 3);

        assert_eq!(symbols.len(), 4); // ceil(10/3) = 4

        let all_symbols: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        let recovered = symbols_to_blocks(&all_symbols, &_manifest);
        assert_eq!(recovered[0].as_ref().unwrap(), &block);
    }

    #[test]
    fn test_exact_multiple_no_extra_padding() {
        let block = vec![0xCC; 8192]; // Exactly 2 * 4096
        let (symbols, _manifest) = blocks_to_symbols(from_ref(&block), 4096);

        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0], block[..4096]);
        assert_eq!(symbols[1], block[4096..]);

        let all_symbols: Vec<Option<Vec<u8>>> = symbols.into_iter().map(Some).collect();
        let recovered = symbols_to_blocks(&all_symbols, &_manifest);
        assert_eq!(recovered[0].as_ref().unwrap(), &block);
    }
}
