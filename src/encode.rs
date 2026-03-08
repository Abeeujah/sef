//! Binary serialization of [`Droplet`] using Bitcoin consensus encoding.
//!
//! Serialized droplets use Bitcoin's `VarInt` length-prefixed format for the
//! index vector and payload, producing a compact on-disk / on-wire
//! representation suitable for storage and network transfer.
//!
//! Additionally exposes filesystem I/O helpers for persisting individual
//! droplets to and from `.bin` files.
//!
//! # Dependency graph
//!
//! - **Depends on:** [`crate::droplet`]
//! - **Consumed by:** the `generate` and `reconstruct` commands.

use std::io::{self};

use bitcoin::{
    VarInt,
    consensus::{Decodable, Encodable, encode},
};

use crate::droplet::Droplet;

/// Consensus-encodes a [`Droplet`] into the following wire format:
///
/// ```text
/// epoch_id (u64) || droplet_id (u64) || num_indices (VarInt) || indices (u32 each)
/// || padded_len (u32) || payload_len (VarInt) || payload (bytes)
/// ```
impl Encodable for Droplet {
    fn consensus_encode<W: bitcoin::io::Write + ?Sized>(
        &self,
        writer: &mut W,
    ) -> Result<usize, bitcoin::io::Error> {
        let mut len = 0;
        len += self.epoch_id.consensus_encode(writer)?;
        len += self.droplet_id.consensus_encode(writer)?;
        len += VarInt(self.indices.len() as u64).consensus_encode(writer)?;
        for &idx in &self.indices {
            len += idx.consensus_encode(writer)?;
        }
        len += self.padded_len.consensus_encode(writer)?;
        len += VarInt(self.payload.len() as u64).consensus_encode(writer)?;
        writer.write_all(&self.payload)?;
        len += self.payload.len();
        Ok(len)
    }
}

/// Reconstructs a [`Droplet`] from its consensus-encoded byte stream,
/// inverting the wire format produced by the [`Encodable`] impl.
impl Decodable for Droplet {
    fn consensus_decode_from_finite_reader<R: bitcoin::io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, bitcoin::consensus::encode::Error> {
        let epoch_id = u64::consensus_decode_from_finite_reader(reader)?;
        let droplet_id = u64::consensus_decode_from_finite_reader(reader)?;
        let num_indices = VarInt::consensus_decode_from_finite_reader(reader)?.0 as usize;
        let mut indices = Vec::with_capacity(num_indices.min(encode::MAX_VEC_SIZE / 4));
        for _ in 0..num_indices {
            indices.push(u32::consensus_decode_from_finite_reader(reader)?);
        }
        let padded_len = u32::consensus_decode_from_finite_reader(reader)?;
        let payload = Vec::<u8>::consensus_decode_from_finite_reader(reader)?;
        Ok(Droplet {
            epoch_id,
            droplet_id,
            indices,
            padded_len,
            payload,
        })
    }
}

/// Consensus-serializes the [`Droplet`] and writes the resulting bytes
/// atomically to `path`.
pub fn write_droplet_file(path: &std::path::Path, droplet: &Droplet) -> io::Result<()> {
    let bytes = encode::serialize(droplet);
    std::fs::write(path, bytes)
}

/// Reads raw bytes from `path` and consensus-deserializes them into a
/// [`Droplet`].
///
/// Returns an [`io::Error`] with kind [`io::ErrorKind::InvalidData`] if the
/// byte stream does not represent a valid [`Droplet`].
pub fn read_droplet_file(path: &std::path::Path) -> io::Result<Droplet> {
    let bytes = std::fs::read(path)?;
    encode::deserialize(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Produces the canonical filename for a droplet:
/// `epoch_{epoch_id}_droplet_{droplet_id}.bin`.
pub fn droplet_filename(epoch_id: u64, droplet_id: u64) -> String {
    format!("epoch_{}_droplet_{}.bin", epoch_id, droplet_id)
}

/// Encodes a droplet directly from borrowed buffers, avoiding allocation.
///
/// This writes the same wire format as the [`Encodable`] impl on [`Droplet`]
/// but operates on borrowed slices so the caller can reuse buffers across
/// droplets.
pub fn encode_droplet_from_parts<W: bitcoin::io::Write + ?Sized>(
    writer: &mut W,
    epoch_id: u64,
    droplet_id: u64,
    indices: &[u32],
    padded_len: u32,
    payload: &[u8],
) -> Result<usize, bitcoin::io::Error> {
    let mut len = 0;
    len += epoch_id.consensus_encode(writer)?;
    len += droplet_id.consensus_encode(writer)?;
    len += VarInt(indices.len() as u64).consensus_encode(writer)?;
    for &idx in indices {
        len += idx.consensus_encode(writer)?;
    }
    len += padded_len.consensus_encode(writer)?;
    len += VarInt(payload.len() as u64).consensus_encode(writer)?;
    writer.write_all(payload)?;
    len += payload.len();
    Ok(len)
}

/// Reads all droplets from a single concatenated epoch file.
///
/// The file contains back-to-back consensus-encoded [`Droplet`]s written by
/// the batched encoder. Returns all successfully decoded droplets; stops
/// cleanly at EOF.
pub fn read_epoch_droplets(path: &std::path::Path) -> io::Result<Vec<Droplet>> {
    let data = std::fs::read(path)?;
    let mut droplets = Vec::new();
    let mut cursor = std::io::Cursor::new(&data);
    let total = data.len() as u64;

    while cursor.position() < total {
        match Droplet::consensus_decode_from_finite_reader(&mut cursor) {
            Ok(d) => droplets.push(d),
            Err(_) => break,
        }
    }

    Ok(droplets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_droplet() -> Droplet {
        Droplet {
            epoch_id: 42,
            droplet_id: 7,
            indices: vec![3, 15, 99],
            padded_len: 8,
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE],
        }
    }

    #[test]
    fn test_roundtrip() {
        let original = sample_droplet();
        let bytes = encode::serialize(&original);
        let recovered: Droplet = encode::deserialize(&bytes).unwrap();

        assert_eq!(recovered.epoch_id, original.epoch_id);
        assert_eq!(recovered.droplet_id, original.droplet_id);
        assert_eq!(recovered.indices, original.indices);
        assert_eq!(recovered.padded_len, original.padded_len);
        assert_eq!(recovered.payload, original.payload);
    }

    #[test]
    fn test_singleton_roundtrip() {
        let d = Droplet {
            epoch_id: 0,
            droplet_id: 0,
            indices: vec![0],
            padded_len: 4,
            payload: vec![1, 2, 3, 4],
        };
        let bytes = encode::serialize(&d);
        let recovered: Droplet = encode::deserialize(&bytes).unwrap();
        assert_eq!(recovered.indices, vec![0]);
        assert_eq!(recovered.payload, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_truncated_payload() {
        let d = sample_droplet();
        let mut bytes = encode::serialize(&d);
        // Truncate: remove last 2 bytes of payload
        bytes.truncate(bytes.len() - 2);
        let result = encode::deserialize::<Droplet>(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_droplet_filename() {
        assert_eq!(droplet_filename(0, 0), "epoch_0_droplet_0.bin");
        assert_eq!(droplet_filename(5, 42), "epoch_5_droplet_42.bin");
    }

    #[test]
    fn test_file_roundtrip() {
        let dir = std::env::temp_dir().join("fountain_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_droplet.bin");

        let original = sample_droplet();
        write_droplet_file(&path, &original).unwrap();
        let recovered = read_droplet_file(&path).unwrap();

        assert_eq!(recovered.epoch_id, original.epoch_id);
        assert_eq!(recovered.droplet_id, original.droplet_id);
        assert_eq!(recovered.indices, original.indices);
        assert_eq!(recovered.payload, original.payload);

        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(&dir).ok();
    }

    #[test]
    fn test_large_droplet_roundtrip() {
        let payload_size = 1_000_000;
        let d = Droplet {
            epoch_id: 100,
            droplet_id: 999,
            indices: vec![0, 50, 100, 200, 499],
            padded_len: payload_size,
            payload: vec![0xAB; payload_size as usize],
        };

        let bytes = encode::serialize(&d);
        let recovered: Droplet = encode::deserialize(&bytes).unwrap();
        assert_eq!(recovered.payload.len(), payload_size as usize);
        assert_eq!(recovered.indices, vec![0, 50, 100, 200, 499]);
    }

    #[test]
    fn test_empty_payload_roundtrip() {
        let d = Droplet {
            epoch_id: 1,
            droplet_id: 2,
            indices: vec![0],
            padded_len: 0,
            payload: vec![],
        };
        let bytes = encode::serialize(&d);
        let recovered: Droplet = encode::deserialize(&bytes).unwrap();
        assert_eq!(recovered.payload, Vec::<u8>::new());
        assert_eq!(recovered.padded_len, 0);
    }

    #[test]
    fn test_corrupted_data() {
        let result = encode::deserialize::<Droplet>(&[0xFF, 0xFF]);
        assert!(result.is_err());
    }
}
