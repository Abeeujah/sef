use std::io::{self};

use bitcoin::{
    VarInt,
    consensus::{Decodable, Encodable, encode},
};

use crate::droplet::Droplet;

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

/// Write a droplet to a file at the given path.
pub fn write_droplet_file(path: &std::path::Path, droplet: &Droplet) -> io::Result<()> {
    let bytes = encode::serialize(droplet);
    std::fs::write(path, bytes)
}

/// Read a droplet from a file at the given path.
pub fn read_droplet_file(path: &std::path::Path) -> io::Result<Droplet> {
    let bytes = std::fs::read(path)?;
    encode::deserialize(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Generate the canonical filename for a droplet.
pub fn droplet_filename(epoch_id: u64, droplet_id: u64) -> String {
    format!("epoch_{}_droplet_{}.bin", epoch_id, droplet_id)
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
